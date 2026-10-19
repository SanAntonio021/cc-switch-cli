//! Offline, provenance-bound local skill deployment through the service layer.
//! The caller exports a reviewed Git commit. No runtime directories are staging inputs.
use super::*;
use serde_json::{json, Value};

fn invalid(message: impl Into<String>) -> AppError { AppError::InvalidInput(message.into()) }

fn validate_segment(value: &str) -> bool {
    !value.is_empty() && value != "." && value != ".."
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

fn provenance(repo: &str, path: &str, commit: &str, name: &str) -> Result<String, AppError> {
    let repo_parts: Vec<_> = repo.split('/').collect();
    if repo_parts.len() != 2 || !repo_parts.iter().all(|p| validate_segment(p))
        || !validate_segment(name) || name.starts_with('.')
        || !path.split('/').all(validate_segment) || path.rsplit('/').next() != Some(name)
        || commit.len() != 40 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid("Invalid local skill source identity/path/commit"));
    }
    Ok(format!("https://github.com/{repo}/blob/{}/{path}/SKILL.md", commit.to_ascii_lowercase()))
}

fn same_source(url: &str, repo: &str, path: &str) -> bool {
    let prefix = format!("https://github.com/{repo}/blob/");
    let Some(rest) = url.strip_prefix(&prefix) else { return false; };
    let Some((commit, tail)) = rest.split_once('/') else { return false; };
    commit.len() == 40 && commit.bytes().all(|b| b.is_ascii_hexdigit())
        && tail == format!("{path}/SKILL.md")
}

fn reject_links(path: &Path) -> Result<(), AppError> {
    for ancestor in path.ancestors() {
        if let Ok(meta) = fs::symlink_metadata(ancestor) {
            #[cfg(windows)]
            {
                use std::os::windows::fs::MetadataExt;
                if meta.file_attributes() & 0x400 != 0 { return Err(invalid("Reparse point in local source path")); }
            }
            if meta.file_type().is_symlink() { return Err(invalid("Link in local source path")); }
        }
    }
    let meta = fs::symlink_metadata(path).map_err(|e| AppError::io(path, e))?;
    if meta.is_dir() {
        for entry in fs::read_dir(path).map_err(|e| AppError::io(path, e))? {
            reject_links(&entry.map_err(|e| AppError::io(path, e))?.path())?;
        }
    } else if !meta.is_file() { return Err(invalid("Local source contains a non-regular file")); }
    Ok(())
}

// Unlike marketplace hashes, private publication includes hidden files and
// length-frames names/content. All-tree readback must protect user edits too.
fn local_tree_hash(root: &Path) -> Result<String, AppError> {
    use sha2::{Digest, Sha256};
    fn collect(root: &Path, files: &mut Vec<PathBuf>) -> Result<(), AppError> {
        for entry in fs::read_dir(root).map_err(|e| AppError::io(root, e))? {
            let path = entry.map_err(|e| AppError::io(root, e))?.path();
            if path.is_dir() { collect(&path, files)?; } else { files.push(path); }
        }
        Ok(())
    }
    reject_links(root)?;
    let mut files = Vec::new(); collect(root, &mut files)?; files.sort();
    let mut digest = Sha256::new();
    for file in files {
        let name = file.strip_prefix(root).map_err(|_| invalid("Hash path escaped root"))?
            .to_string_lossy().replace('\\', "/");
        let bytes = fs::read(&file).map_err(|e| AppError::io(&file, e))?;
        digest.update((name.len() as u64).to_le_bytes()); digest.update(name.as_bytes());
        digest.update((bytes.len() as u64).to_le_bytes()); digest.update(bytes);
    }
    Ok(format!("local-sha256:{:x}", digest.finalize()))
}

fn abort_updates(mut updates: Vec<in_place::Update>, cause: AppError) -> AppError {
    let mut failures = Vec::new();
    while let Some(mut update) = updates.pop() {
        match update.rollback() {
            Ok(()) => { if let Err(e) = update.commit() { failures.push(e.to_string()); } }
            Err(e) => failures.push(e.to_string()),
        }
    }
    AppError::Message(format!("{cause}; {}", if failures.is_empty() {
        "local skill rollback verified".to_string()
    } else { format!("recovery incomplete; retained journals: {}", failures.join("; ")) }))
}

impl SkillService {
    /// No DB creation/migration, no settings migration, and no runtime writes.
    pub fn local_info(name: &str) -> Result<Value, AppError> {
        if !validate_segment(name) { return Err(invalid("Invalid skill name")); }
        if !crate::config::get_app_config_dir().join("cc-switch.db").exists() {
            return Ok(json!({"found": false, "skill": null}));
        }
        let db = Database::open_readonly_current_schema()?;
        let skill = db.get_all_installed_skills()?.into_values()
            .find(|s| s.directory.eq_ignore_ascii_case(name));
        Ok(json!({"found": skill.is_some(), "skill": skill}))
    }

    /// Install or update one managed local source, preserving every app flag.
    /// DB is written last. File transactions roll back on pre-commit failures.
    /// A post-commit cleanup failure is explicit; journals are kept for recovery.
    pub fn install_local(source: &Path, name: &str, repo: &str, path: &str,
        commit: &str, app: &AppType) -> Result<Value, AppError> {
        Self::install_local_checked(source, name, repo, path, commit, app, |_| Ok(()))
    }

    fn install_local_checked<F: FnOnce(&Database) -> Result<(), AppError>>(
        source: &Path, name: &str, repo: &str, path: &str, commit: &str,
        app: &AppType, before_save: F,
    ) -> Result<Value, AppError> {
        if !matches!(app, AppType::Codex) { return Err(invalid("Local installation defaults must target codex")); }
        Self::require_valid_directory(name)?;
        let readme_url = provenance(repo, path, commit, name)?;
        if !source.is_absolute() || !source.is_dir() { return Err(invalid("Source must be an absolute directory")); }
        reject_links(source)?;
        let metadata = Self::parse_skill_metadata_static(&source.join("SKILL.md"))?;
        if metadata.name.as_deref() != Some(name) || metadata.description.as_deref().unwrap_or("").trim().is_empty() {
            return Err(invalid("SKILL.md requires matching name and a nonempty description"));
        }
        let _guard = skill_state_write_guard();
        let db = Database::init()?;
        let baseline = db.capture_local_skill_baseline(name)?;
        let existing = baseline.skill.clone();
        if let Some(old) = &existing {
            if old.id != format!("local:{name}") || old.directory != name
                || old.repo_owner.is_some() || old.repo_name.is_some() || old.repo_branch.is_some()
                || !same_source(old.readme_url.as_deref().unwrap_or(""), repo, path) {
                return Err(invalid("Foreign skill name/source conflict; refusing replacement"));
            }
        }
        let ssot = Self::get_ssot_dir()?.join(name);
        let source_canonical = fs::canonicalize(source).map_err(|e| AppError::io(source, e))?;
        // Runtime content is never an acceptable authoritative source, even for a new name.
        for root in std::iter::once(Self::get_ssot_dir()?)
            .chain(Self::supported_skill_apps().filter_map(|a| Self::get_app_skills_dir(&a).ok())) {
            if root.exists() && source_canonical.starts_with(fs::canonicalize(&root).map_err(|e| AppError::io(&root, e))?) {
                return Err(invalid("Runtime skill directories cannot be local sources"));
            }
        }
        if existing.is_none() && fs::symlink_metadata(&ssot).is_ok() {
            return Err(invalid("Unmanaged SSOT directory conflict"));
        }
        if let Some(old) = &existing {
            if old.content_hash.as_deref() != Some(local_tree_hash(&ssot)?.as_str()) {
                return Err(invalid("Installed SSOT has local edits; refusing update"));
            }
        }
        let apps = existing.as_ref().map(|s| s.apps.clone()).unwrap_or_else(|| SkillApps::only(app));
        let mut destinations = vec![ssot.clone()];
        for target in Self::supported_skill_apps().filter(|a| apps.is_enabled_for(a)) {
            let dest = Self::get_app_skills_dir(&target)?.join(name);
            if Self::is_symlink(&dest) {
                if existing.is_some() && fs::canonicalize(&dest).ok() == fs::canonicalize(&ssot).ok() { continue; }
                return Err(invalid("Foreign application link conflict"));
            }
            if dest.exists() {
                let Some(old) = &existing else { return Err(invalid("Unmanaged application directory conflict")); };
                if old.content_hash.as_deref() != Some(local_tree_hash(&dest)?.as_str()) {
                    return Err(invalid("Application skill has local edits; refusing update"));
                }
            }
            destinations.push(dest);
        }
        // Prepare every file tree before any deployment mutation. Copies for new
        // projections avoid needing symlink privileges; existing SSOT links survive.
        let mut prepared = Vec::new();
        for dest in &destinations {
            match in_place::Update::prepare(source, dest) {
                Ok(update) => prepared.push(update),
                Err(error) => {
                    for update in prepared { let _ = update.commit(); }
                    return Err(error);
                }
            }
        }
        let mut applied = Vec::new();
        for mut update in prepared {
            if let Err(error) = update.apply() { return Err(abort_updates(applied, error)); }
            applied.push(update);
        }
        let content_hash = match local_tree_hash(&ssot) {
            Ok(hash) => hash,
            Err(error) => return Err(abort_updates(applied, error)),
        };
        let now = Utc::now().timestamp();
        let skill = InstalledSkill {
            id: format!("local:{name}"), name: name.to_string(), description: metadata.description,
            directory: name.to_string(), repo_owner: None, repo_name: None, repo_branch: None,
            readme_url: Some(readme_url.clone()), apps,
            installed_at: existing.as_ref().map(|s| s.installed_at).unwrap_or(now),
            content_hash: Some(content_hash.clone()), updated_at: now,
        };
        if let Err(error) = before_save(&db) { return Err(abort_updates(applied, error)); }
        if let Err(error) = db.save_local_skill_if_unchanged(&baseline, &skill) { return Err(abort_updates(applied, error)); }
        let action = match &existing {
            None => "installed",
            Some(old) if old.content_hash.as_deref() == Some(content_hash.as_str())
                && old.readme_url.as_deref() == Some(readme_url.as_str()) => "unchanged",
            Some(_) => "updated",
        };
        let mut cleanup = Vec::new();
        for update in applied { if let Err(error) = update.commit() { cleanup.push(error.to_string()); } }
        if !cleanup.is_empty() {
            return Err(AppError::Message(format!("Local deployment committed; cleanup incomplete: {}", cleanup.join("; "))));
        }
        Ok(json!({"action": action, "skill": skill, "sourceRepo": repo,
            "sourcePath": path, "sourceCommit": commit.to_ascii_lowercase()}))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn source(root: &Path, text: &str) -> PathBuf {
        let dir = root.join("export").join("demo");
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("SKILL.md"), format!("---\nname: demo\ndescription: Test local source\n---\n{text}\n")).unwrap();
        dir
    }
    fn install(dir: &Path, commit: char) -> Result<Value, AppError> {
        SkillService::install_local(dir, "demo", "owner/private", "private-skills/demo",
            &commit.to_string().repeat(40), &AppType::Codex)
    }
    #[test]
    fn local_install_update_preserves_apps_other_skills_and_bytes() {
        let home = tempfile::tempdir().unwrap(); let _env = crate::test_support::TestEnvGuard::isolated(home.path());
        let input = source(home.path(), "first");
        assert_eq!(install(&input, 'a').unwrap()["action"], "installed");
        SkillService::toggle_app("demo", &AppType::Claude, true).unwrap();
        let untouched = SkillService::get_ssot_dir().unwrap().join("unrelated");
        fs::create_dir_all(&untouched).unwrap(); fs::write(untouched.join("keep.bin"), [0, 255, 13, 10]).unwrap();
        source(home.path(), "second"); fs::write(input.join("raw.bin"), [0, 255, 13, 10]).unwrap();
        let result = install(&input, 'b').unwrap();
        assert_eq!(result["action"], "updated"); assert_eq!(result["skill"]["apps"]["claude"], true);
        assert_eq!(result["skill"]["apps"]["codex"], true);
        assert_eq!(fs::read(untouched.join("keep.bin")).unwrap(), [0, 255, 13, 10]);
        for app in [AppType::Codex, AppType::Claude] {
            assert_eq!(fs::read(SkillService::get_app_skills_dir(&app).unwrap().join("demo/raw.bin")).unwrap(), [0,255,13,10]);
        }
        assert_eq!(install(&input, 'b').unwrap()["action"], "unchanged");
    }
    #[test]
    fn local_schema20_update_preserves_pi_mcp_unknown_skill_fields_and_settings() {
        let home = tempfile::tempdir().unwrap(); let _env = crate::test_support::TestEnvGuard::isolated(home.path());
        let input = source(home.path(), "first");
        install(&input, 'a').unwrap();
        {
            let db = Database::init().unwrap(); let conn = db.conn.lock().unwrap();
            assert_eq!(Database::get_user_version(&conn).unwrap(), 20);
            conn.execute_batch("INSERT INTO mcp_servers(id,name,server_config,enabled_codex,enabled_mcode,enabled_pi) VALUES('pi-sentinel','Pi sentinel','{}',1,1,1); ALTER TABLE skills ADD COLUMN schema20_extra TEXT; UPDATE skills SET enabled_mcode=1,schema20_extra='keep'; INSERT INTO settings(key,value) VALUES('schema20_sentinel','keep');").unwrap();
        }
        assert_eq!(SkillService::local_info("demo").unwrap()["found"], true);
        source(home.path(), "second"); install(&input, 'b').unwrap();
        let db = Database::init().unwrap(); let conn = db.conn.lock().unwrap();
        let mcp: (i64,i64,i64) = conn.query_row("SELECT enabled_codex,enabled_mcode,enabled_pi FROM mcp_servers WHERE id='pi-sentinel'",[],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).unwrap();
        assert_eq!(mcp,(1,1,1));
        let skill: (i64,String) = conn.query_row("SELECT enabled_mcode,schema20_extra FROM skills WHERE directory='demo'",[],|r|Ok((r.get(0)?,r.get(1)?))).unwrap();
        assert_eq!(skill,(1,"keep".into()));
        assert_eq!(conn.query_row("SELECT value FROM settings WHERE key='schema20_sentinel'",[],|r|r.get::<_,String>(0)).unwrap(),"keep");
    }

    #[test]
    fn local_install_rejects_foreign_source_and_user_edits() {
        let home = tempfile::tempdir().unwrap(); let _env = crate::test_support::TestEnvGuard::isolated(home.path());
        let input = source(home.path(), "first"); install(&input, 'a').unwrap();
        let db = Database::init().unwrap(); let mut record = db.get_installed_skill("local:demo").unwrap().unwrap();
        record.readme_url = Some(format!("https://github.com/other/repo/blob/{}/private-skills/demo/SKILL.md", "a".repeat(40)));
        db.save_skill(&record).unwrap(); assert!(install(&input, 'b').unwrap_err().to_string().contains("Foreign"));
        record.readme_url = Some(provenance("owner/private", "private-skills/demo", &"a".repeat(40), "demo").unwrap());
        db.save_skill(&record).unwrap();
        fs::write(SkillService::get_app_skills_dir(&AppType::Codex).unwrap().join("demo/SKILL.md"), "user edit").unwrap();
        assert!(install(&input, 'b').unwrap_err().to_string().contains("local edits"));
    }
    #[test]
    fn local_info_missing_does_not_initialize_database() {
        let home = tempfile::tempdir().unwrap(); let _env = crate::test_support::TestEnvGuard::isolated(home.path());
        assert_eq!(SkillService::local_info("demo").unwrap()["found"], false);
        assert!(!home.path().join(".cc-switch/cc-switch.db").exists());
    }
    #[test]
    fn local_install_rejects_bad_structure_and_identity() {
        let home = tempfile::tempdir().unwrap(); let _env = crate::test_support::TestEnvGuard::isolated(home.path());
        let input = source(home.path(), "first");
        assert!(SkillService::install_local(&input, "../demo", "owner/private", "private-skills/demo", &"a".repeat(40), &AppType::Codex).is_err());
        fs::write(input.join("SKILL.md"), "no metadata").unwrap();
        assert!(install(&input, 'a').is_err());
    }
    #[test]
    fn local_install_protects_hidden_user_edits() {
        let home = tempfile::tempdir().unwrap(); let _env = crate::test_support::TestEnvGuard::isolated(home.path());
        let input = source(home.path(), "first");
        fs::write(input.join(".private"), "original").unwrap(); install(&input, 'a').unwrap();
        let ssot = SkillService::get_ssot_dir().unwrap().join("demo");
        fs::write(ssot.join(".private"), "user edit").unwrap();
        assert!(install(&input, 'b').unwrap_err().to_string().contains("local edits"));
        assert_eq!(fs::read_to_string(ssot.join(".private")).unwrap(), "user edit");
    }
    fn concurrent_edit(change_source: bool) {
        let home = tempfile::tempdir().unwrap(); let _env = crate::test_support::TestEnvGuard::isolated(home.path());
        let input = source(home.path(), "first"); install(&input, 'a').unwrap();
        source(home.path(), "second");
        let result = SkillService::install_local_checked(&input, "demo", "owner/private", "private-skills/demo",
            &"b".repeat(40), &AppType::Codex, |db| {
                let mut row = db.get_installed_skill("local:demo")?.unwrap();
                if change_source { row.readme_url = Some("external source edit".to_string()); }
                else { row.apps.claude = true; }
                db.save_skill(&row)
            });
        assert!(result.unwrap_err().to_string().contains("Concurrent"));
        let row = Database::init().unwrap().get_installed_skill("local:demo").unwrap().unwrap();
        if change_source { assert_eq!(row.readme_url.as_deref(), Some("external source edit")); }
        else { assert!(row.apps.claude); }
        assert!(fs::read_to_string(SkillService::get_ssot_dir().unwrap().join("demo/SKILL.md")).unwrap().contains("first"));
        assert!(fs::read_to_string(SkillService::get_app_skills_dir(&AppType::Codex).unwrap().join("demo/SKILL.md")).unwrap().contains("first"));
    }
    #[test]
    fn local_install_preserves_concurrent_app_edit_and_rolls_back_files() { concurrent_edit(false); }
    #[test]
    fn local_install_preserves_concurrent_source_edit_and_rolls_back_files() { concurrent_edit(true); }
    #[test]
    #[cfg(windows)]
    fn local_install_rejects_junction_source() {
        let home = tempfile::tempdir().unwrap(); let _env = crate::test_support::TestEnvGuard::isolated(home.path());
        let input = source(home.path(), "first");
        let linked = home.path().join("linked-source");
        // Windows junctions do not require developer mode or symlink privileges.
        let status = std::process::Command::new("cmd").args(["/c", "mklink", "/J"])
            .arg(&linked).arg(&input).output().unwrap();
        assert!(status.status.success(), "junction fixture failed");
        assert!(install(&linked, 'a').unwrap_err().to_string().contains("Reparse"));
        fs::remove_dir(&linked).unwrap();
    }
    #[test]
    #[cfg(windows)]
    fn local_install_locked_app_rolls_back_ssot_and_database() {
        use std::os::windows::fs::OpenOptionsExt;
        let home = tempfile::tempdir().unwrap(); let _env = crate::test_support::TestEnvGuard::isolated(home.path());
        let input = source(home.path(), "first"); install(&input, 'a').unwrap();
        let dest = SkillService::get_app_skills_dir(&AppType::Codex).unwrap().join("demo/SKILL.md");
        let held = fs::OpenOptions::new().read(true).share_mode(1).open(&dest).unwrap();
        source(home.path(), "second"); assert!(install(&input, 'b').is_err()); drop(held);
        assert!(fs::read_to_string(&dest).unwrap().contains("first"));
        assert!(fs::read_to_string(SkillService::get_ssot_dir().unwrap().join("demo/SKILL.md")).unwrap().contains("first"));
        let record = Database::init().unwrap().get_installed_skill("local:demo").unwrap().unwrap();
        assert!(record.readme_url.unwrap().contains(&"a".repeat(40)));
    }
}

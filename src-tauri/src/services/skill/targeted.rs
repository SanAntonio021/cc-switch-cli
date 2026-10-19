use super::*;
use futures::{stream, StreamExt, TryStreamExt};
use sha1::{Digest, Sha1};

#[derive(Deserialize)]
struct GitObject { sha: String }
#[derive(Deserialize)]
struct GitCommit { sha: String, tree: GitObject }
#[derive(Deserialize)]
struct GitTree { sha: String, tree: Vec<GitEntry>, #[serde(default)] truncated: bool }
#[derive(Deserialize, Clone)]
struct GitEntry { path: String, mode: String, #[serde(rename = "type")] kind: String, sha: String, size: Option<u64> }

fn failure(message: impl Into<String>) -> AppError { AppError::Message(message.into()) }

impl SkillService {
    // Caller holds the skill write guard, including the post-download recheck.
    pub(super) fn reject_pinned_existing_install(name: &str) -> Result<(), AppError> {
        let db = Database::init()?;
        if db.get_all_installed_skills()?.values().any(|s| s.directory.eq_ignore_ascii_case(name))
            || Self::get_ssot_dir()?.join(name).exists()
        {
            return Err(AppError::InvalidInput("Pinned install requires a new skill; use skills update NAME --source-commit SHA for an existing skill".into()));
        }
        Ok(())
    }

    pub(super) fn validate_source_commit(commit: &str) -> Result<(), AppError> {
        if commit.len() != 40 || !commit.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(AppError::InvalidInput("source-commit must be a full 40-character Git SHA".into()));
        }
        Ok(())
    }

    fn validate_targeted_path(path: &str) -> Result<(), AppError> {
        if path.is_empty() { return Err(failure("Empty Git source path")); }
        Self::validate_archive_relative_path(Path::new(path))?;
        for part in path.split('/') {
            let base = part.split('.').next().unwrap_or("").to_ascii_uppercase();
            if part.is_empty() || part == "." || part == ".." || (part.ends_with('.') || part.ends_with(' '))
                || part.chars().any(|c| c.is_control() || "\\:*?\"<>|".contains(c))
                || matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
                || (base.len() == 4 && (base.starts_with("COM") || base.starts_with("LPT")) && matches!(base.as_bytes()[3], b'1'..=b'9'))
            { return Err(failure(format!("Unsafe Git source path: {path}"))); }
        }
        Ok(())
    }

    fn targeted_url(host: &str, segments: &[&str]) -> Result<url::Url, AppError> {
        let mut url = url::Url::parse(host).map_err(|e| failure(e.to_string()))?;
        url.path_segments_mut().map_err(|_| failure("Invalid GitHub URL"))?.extend(segments.iter().copied());
        Ok(url)
    }

    // Bound both declared and streamed response sizes. A failed download remains
    // in a TempDir, before the existing SSOT/database/app transaction is entered.
    async fn targeted_bytes(url: url::Url, limit: u64) -> Result<Vec<u8>, AppError> {
        let mut response = crate::proxy::http_client::get().get(url)
            .header(reqwest::header::USER_AGENT, "cc-switch")
            .timeout(std::time::Duration::from_secs(600)).send().await
            .map_err(|e| failure(format!("GitHub targeted download failed: {e}")))?;
        if !response.status().is_success() { return Err(failure(format!("GitHub targeted download: HTTP {}", response.status()))); }
        if response.content_length().is_some_and(|n| n > limit) { return Err(failure("GitHub response exceeds size budget")); }
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|e| failure(e.to_string()))? {
            if (bytes.len() as u64).saturating_add(chunk.len() as u64) > limit { return Err(failure("GitHub response exceeds size budget")); }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    async fn targeted_json<T: serde::de::DeserializeOwned>(repo: &SkillRepo, tail: &[&str]) -> Result<T, AppError> {
        let mut segments = vec!["repos", repo.owner.as_str(), repo.name.as_str(), "git"];
        segments.extend_from_slice(tail);
        let url = Self::targeted_url("https://api.github.com/", &segments)?;
        let bytes = Self::targeted_bytes(url, 16 * 1024 * 1024).await?;
        serde_json::from_slice(&bytes).map_err(|e| failure(format!("Invalid GitHub metadata: {e}")))
    }

    fn validate_targeted_tree(tree: &GitTree, prefix: &Path) -> Result<u64, AppError> {
        if tree.truncated || tree.tree.len() > MAX_SKILL_ARCHIVE_ENTRIES { return Err(failure("Incomplete or oversized GitHub skill tree")); }
        let mut seen = HashMap::new();
        let mut budget = (prefix.components().count() as u64) * SKILL_ARCHIVE_ENTRY_COST;
        for entry in &tree.tree {
            Self::validate_targeted_path(&entry.path)?;
            Self::validate_source_commit(&entry.sha)?;
            Self::validate_archive_relative_path(&prefix.join(&entry.path))?;
            if seen.insert(entry.path.to_lowercase(), (entry.path.as_str(), entry.kind.as_str())).is_some() { return Err(failure("Colliding GitHub source paths")); }
            let bytes = match (entry.kind.as_str(), entry.mode.as_str()) {
                ("tree", "040000") => 0,
                ("blob", "100644" | "100755") => entry.size.ok_or_else(|| failure("Missing Git blob size"))?,
                _ => return Err(failure("GitHub source contains a symlink, submodule or unsupported entry")),
            };
            Self::charge_archive_budget(&mut budget, SKILL_ARCHIVE_ENTRY_COST, MAX_SKILL_ARCHIVE_TOTAL_BYTES)?;
            Self::charge_archive_budget(&mut budget, bytes, MAX_SKILL_ARCHIVE_TOTAL_BYTES)?;
        }
        for entry in &tree.tree {
            let mut parent = Path::new(&entry.path).parent();
            while let Some(path) = parent.filter(|p| !p.as_os_str().is_empty()) {
                let text = path.to_string_lossy().replace('\\', "/");
                match seen.get(&text.to_lowercase()) {
                    Some((actual, "tree")) if *actual == text.as_str() => {},
                    _ => return Err(failure("Missing, colliding or non-directory Git path ancestor")),
                }
                parent = path.parent();
            }
        }
        let download_size = tree.tree.iter().filter_map(|e| e.size).try_fold(0u64, |n, s| n.checked_add(s)).ok_or_else(|| failure("Git download size overflow"))?;
        if download_size > MAX_SKILL_ARCHIVE_DOWNLOAD_BYTES { return Err(failure("Target skill exceeds Git download budget")); }
        if !tree.tree.iter().any(|e| e.path == "SKILL.md" && e.kind == "blob") { return Err(failure("Target directory has no SKILL.md")); }
        Ok(download_size)
    }

    fn verify_targeted_blob(entry: &GitEntry, bytes: &[u8]) -> Result<(), AppError> {
        if entry.size != Some(bytes.len() as u64) { return Err(failure(format!("Git blob size mismatch: {}", entry.path))); }
        let mut hash = Sha1::new();
        hash.update(format!("blob {}\0", bytes.len()).as_bytes()); hash.update(bytes);
        if format!("{:x}", hash.finalize()) != entry.sha.to_ascii_lowercase() { return Err(failure(format!("Git blob hash mismatch: {}", entry.path))); }
        Ok(())
    }

    fn write_targeted_blob(entry: &GitEntry, bytes: &[u8], target: &Path) -> Result<(), AppError> {
        Self::verify_targeted_blob(entry, bytes)?;
        let dest = target.join(&entry.path);
        if let Some(parent) = dest.parent() { fs::create_dir_all(parent).map_err(|e| AppError::io(parent,e))?; }
        use std::io::Write;
        let mut file = fs::OpenOptions::new().write(true).create_new(true).open(&dest)
            .map_err(|e| AppError::io(&dest,e))?;
        file.write_all(bytes).map_err(|e| AppError::io(&dest,e))
    }

    pub(super) async fn download_targeted_skill(&self, repo: &SkillRepo, commit: &str, source: &Path) -> Result<PathBuf, AppError> {
        Self::validate_source_commit(commit)?;
        // Reuse the existing strict public GitHub identity validation.
        Self::github_archive_url(&repo.owner, &repo.name, &repo.branch)?;
        let source_text = source.to_string_lossy().replace('\\', "/");
        if !source_text.is_empty() { Self::validate_targeted_path(&source_text)?; }
        let metadata: GitCommit = Self::targeted_json(repo, &["commits", commit]).await?;
        if !metadata.sha.eq_ignore_ascii_case(commit) { return Err(failure("GitHub returned a different source commit")); }
        let mut tree_sha = metadata.tree.sha;
        Self::validate_source_commit(&tree_sha)?;
        // Walk only ancestors, avoiding recursive enumeration of the large repository.
        for part in source_text.split('/').filter(|p| !p.is_empty()) {
            let tree: GitTree = Self::targeted_json(repo, &["trees", &tree_sha]).await?;
            if tree.truncated || !tree.sha.eq_ignore_ascii_case(&tree_sha) { return Err(failure("Incomplete or mismatched ancestor tree")); }
            let entry = tree.tree.iter().find(|e| e.path == part && e.kind == "tree" && e.mode == "040000").ok_or_else(|| failure(format!("Git source directory not found: {source_text}")))?;
            Self::validate_source_commit(&entry.sha)?;
            tree_sha = entry.sha.clone();
        }
        let mut url = Self::targeted_url("https://api.github.com/", &["repos", &repo.owner, &repo.name, "git", "trees", &tree_sha])?;
        url.query_pairs_mut().append_pair("recursive", "1");
        let bytes = Self::targeted_bytes(url, 16 * 1024 * 1024).await?;
        let tree: GitTree = serde_json::from_slice(&bytes).map_err(|e| failure(e.to_string()))?;
        if !tree.sha.eq_ignore_ascii_case(&tree_sha) { return Err(failure("Mismatched target tree")); }
        Self::validate_targeted_tree(&tree, source)?;
        let temp = tempfile::tempdir().map_err(|e| failure(e.to_string()))?;
        let target = temp.path().join(source);
        fs::create_dir_all(&target).map_err(|e| AppError::io(&target, e))?;
        // Every directory/path was validated before any file is written.
        let mut directories: Vec<_> = tree.tree.iter().filter(|e| e.kind == "tree").collect();
        directories.sort_by_key(|e| e.path.split('/').count());
        for entry in directories {
            let dir = target.join(&entry.path); fs::create_dir(&dir).map_err(|e| AppError::io(&dir, e))?;
        }
        stream::iter(tree.tree.into_iter().filter(|e| e.kind == "blob").map(|entry| {
            let target = target.clone(); let source_text = source_text.clone();
            async move {
                let full = if source_text.is_empty() { entry.path.clone() } else { format!("{source_text}/{}", entry.path) };
                let mut segments = vec![repo.owner.as_str(), repo.name.as_str(), commit]; segments.extend(full.split('/'));
                let url = Self::targeted_url("https://raw.githubusercontent.com/", &segments)?;
                let bytes = Self::targeted_bytes(url, entry.size.unwrap()).await?;
                Self::write_targeted_blob(&entry, &bytes, &target)?;
                Ok::<(),AppError>(())
            }
        })).buffer_unordered(8).try_collect::<Vec<_>>().await?;
        Ok(temp.keep())
    }
}

#[cfg(test)]
mod targeted_download_tests {
    use super::*;
    fn entry(path: &str, kind: &str, mode: &str, size: Option<u64>) -> GitEntry { GitEntry { path:path.into(), kind:kind.into(), mode:mode.into(), size, sha:"e69de29bb2d1d6434b8b29ae775ad8c2e48c5391".into() } }
    fn tree(entries: Vec<GitEntry>) -> GitTree { GitTree { sha:"0".repeat(40), truncated:false, tree:entries } }
    #[test] fn validates_git_blob_bytes_and_size() { let e=entry("SKILL.md","blob","100644",Some(0)); assert!(SkillService::verify_targeted_blob(&e,b"").is_ok()); assert!(SkillService::verify_targeted_blob(&e,b"bad").is_err()); }
    #[test] fn rejects_unsafe_source_paths() { for p in ["../escape","a\\b","/abs","a//b","con.txt","a:ads","x/..","x.","x "] { assert!(SkillService::validate_targeted_path(p).is_err(),"{p}"); } assert!(SkillService::validate_targeted_path("skill-check/scripts/测试.py").is_ok()); }
    #[test] fn rejects_incomplete_unsupported_and_case_colliding_trees() { let skill=entry("SKILL.md","blob","100644",Some(0)); for extra in [entry("link","blob","120000",Some(1)),entry("sub","commit","160000",None),entry("skill.md","blob","100644",Some(0))] { assert!(SkillService::validate_targeted_tree(&tree(vec![skill.clone(),extra]),Path::new("skill-check")).is_err()); } let mut t=tree(vec![skill]);t.truncated=true; assert!(SkillService::validate_targeted_tree(&t,Path::new("")).is_err()); }
    #[test] fn rejects_excessive_blob_budget_before_writes() { let t=tree(vec![entry("SKILL.md","blob","100644",Some(MAX_SKILL_ARCHIVE_DOWNLOAD_BYTES+1))]); assert!(SkillService::validate_targeted_tree(&t,Path::new("skill-check")).is_err()); }
    #[test] fn rejects_implicit_parent_case_collisions_and_file_ancestors() {
        let skill=entry("SKILL.md","blob","100644",Some(0));
        for entries in [
            vec![skill.clone(),entry("a","tree","040000",None),entry("A/b","blob","100644",Some(0))],
            vec![skill.clone(),entry("a","blob","100644",Some(0)),entry("a/b","blob","100644",Some(0))],
            vec![skill.clone(),entry("missing/b","blob","100644",Some(0))],
        ] { assert!(SkillService::validate_targeted_tree(&tree(entries),Path::new("skill-check")).is_err()); }
        assert!(SkillService::validate_targeted_tree(&tree(vec![skill,entry("a","tree","040000",None),entry("a/b","blob","100644",Some(0))]),Path::new("skill-check")).is_ok());
    }
    #[test]
    #[serial_test::serial(home_settings)]
    fn pinned_install_rejects_existing_without_mutation() {
        let temp = tempfile::tempdir().unwrap();
        let _env = crate::test_support::TestEnvGuard::isolated(temp.path());
        assert!(SkillService::reject_pinned_existing_install("demo").is_ok());
        let root = SkillService::get_ssot_dir().unwrap().join("demo");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("SKILL.md"), b"old").unwrap();
        assert!(SkillService::reject_pinned_existing_install("demo").is_err());
        assert_eq!(fs::read(root.join("SKILL.md")).unwrap(), b"old");
    }
    #[test]
    fn never_overwrites_downloaded_blob() {
        let temp = tempfile::tempdir().unwrap();
        let e=entry("SKILL.md","blob","100644",Some(0));
        SkillService::write_targeted_blob(&e,b"",temp.path()).unwrap();
        assert!(SkillService::write_targeted_blob(&e,b"",temp.path()).is_err());
    }
    #[cfg(windows)]
    #[test]
    fn preserves_windows_filesystem_name_identity() {
        let temp = tempfile::tempdir().unwrap();
        let first=entry("Name.txt","blob","100644",Some(0));
        let second=entry("name.txt","blob","100644",Some(0));
        SkillService::write_targeted_blob(&first,b"",temp.path()).unwrap();
        assert!(SkillService::write_targeted_blob(&second,b"",temp.path()).is_err());
        // Unicode ordinal comparison is not the filesystem's equivalence rule.
        // If the filesystem aliases these names, never overwrite; otherwise
        // preserve both independent files exactly.
        let first=entry("σ.txt","blob","100644",Some(0));
        let second=entry("ς.txt","blob","100644",Some(0));
        SkillService::write_targeted_blob(&first,b"",temp.path()).unwrap();
        let aliased=temp.path().join(&second.path).exists();
        let result=SkillService::write_targeted_blob(&second,b"",temp.path());
        assert_eq!(result.is_err(),aliased);
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(),if aliased {2} else {3});
    }
    #[test] fn requires_full_commit() { for s in ["main","abc","000000000000000000000000000000000000000g"] { assert!(SkillService::validate_source_commit(s).is_err()); } assert!(SkillService::validate_source_commit(&"a".repeat(40)).is_ok()); }
}

#[cfg(test)]
mod targeted_http_tests {
    use super::*;
    use std::io::{Read, Write};
    fn server(body: &'static [u8]) -> (url::Url, std::thread::JoinHandle<()>) {
        server_with_length(body, body.len())
    }
    fn server_with_length(body: &'static [u8], length: usize) -> (url::Url, std::thread::JoinHandle<()>) {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            socket.set_read_timeout(Some(std::time::Duration::from_secs(10))).unwrap();
            let mut request = [0u8; 4096]; socket.read(&mut request).unwrap();
            write!(socket,"HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",length).unwrap();
            let _ = socket.write_all(body);
        });
        (url::Url::parse(&format!("http://{address}/blob")).unwrap(), handle)
    }
    #[tokio::test]
    async fn targeted_download_tests_real_http_rejects_oversize_and_hash_before_writing() {
        let temp = tempfile::tempdir().unwrap();
        let (url, thread) = server(b"abc");
        assert!(SkillService::targeted_bytes(url,2).await.is_err()); thread.join().unwrap();
        let (url, thread) = server(b"abc");
        let bytes=SkillService::targeted_bytes(url,3).await.unwrap(); thread.join().unwrap();
        let entry=GitEntry { path:"nested/SKILL.md".into(), kind:"blob".into(),mode:"100644".into(),size:Some(3),sha:"0".repeat(40) };
        assert!(SkillService::write_targeted_blob(&entry,&bytes,temp.path()).is_err());
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(),0);
        let mut valid=entry; valid.sha="f2ba8f84ab5c1bce84a7b441cb1959cfc7093b7f".into();
        SkillService::write_targeted_blob(&valid,&bytes,temp.path()).unwrap();
        assert_eq!(fs::read(temp.path().join("nested/SKILL.md")).unwrap(),b"abc");
    }
    #[tokio::test]
    async fn targeted_download_tests_real_http_truncated_body_does_not_write() {
        let temp = tempfile::tempdir().unwrap();
        let existing = temp.path().join("SKILL.md");
        fs::write(&existing, b"old skill bytes").unwrap();
        // The budget permits the declared length, so failure must come from
        // the peer closing the connection before the response is complete.
        let (url, thread) = server_with_length(b"abc", 6);
        let result = SkillService::targeted_bytes(url, 6).await;
        thread.join().unwrap();
        assert!(result.is_err());
        assert_eq!(fs::read(&existing).unwrap(), b"old skill bytes");
        assert!(!temp.path().join("nested/SKILL.md").exists());
        assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
    }
    #[tokio::test]
    async fn targeted_download_tests_real_http_invalid_blob_preserves_destination() {
        let temp = tempfile::tempdir().unwrap();
        let existing = temp.path().join("SKILL.md");
        fs::write(&existing, b"old skill bytes").unwrap();
        let (url, thread) = server(b"abc");
        let bytes = SkillService::targeted_bytes(url, 4).await.unwrap();
        thread.join().unwrap();
        // Exercise both validation failures against a new nested destination
        // and an existing file, using bytes obtained through a real response.
        for (size, sha) in [(4, "f2ba8f84ab5c1bce84a7b441cb1959cfc7093b7f".to_string()), (3, "0".repeat(40))] {
            for path in ["nested/SKILL.md", "SKILL.md"] {
                let entry = GitEntry { path: path.into(), kind: "blob".into(), mode: "100644".into(), size: Some(size), sha: sha.clone() };
                assert!(SkillService::write_targeted_blob(&entry, &bytes, temp.path()).is_err());
                assert_eq!(fs::read(&existing).unwrap(), b"old skill bytes");
                assert!(!temp.path().join("nested").exists());
                assert_eq!(fs::read_dir(temp.path()).unwrap().count(), 1);
            }
        }
    }
}

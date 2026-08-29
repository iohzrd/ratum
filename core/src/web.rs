//! What the pool's and the gateway's status pages share: the stylesheet and the script
//! helpers, in one copy for the three pages. A page holds the markers
//! `<!--shared-css-->` and `<!--shared-js-->` where `assemble` inserts them.

pub const CSS: &str = include_str!("web/page.css");
pub const JS: &str = include_str!("web/page.js");

/// The page with the shared stylesheet and script in place of the markers.
pub fn assemble(page: &str) -> String {
    page.replace("<!--shared-css-->", &format!("<style>\n{CSS}</style>"))
        .replace("<!--shared-js-->", &format!("<script>\n{JS}</script>"))
}

#[cfg(test)]
mod tests {
    #[test]
    fn markers_are_replaced() {
        let out = super::assemble("<head><!--shared-css--></head><!--shared-js-->");
        assert!(out.contains("--bg:"));
        assert!(out.contains("function card("));
        assert!(!out.contains("<!--shared"));
    }
}

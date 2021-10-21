use urlencoding::encode;

pub fn encode_url_path(path: &str) -> String {
    encode(path).replace("%2F", "/")
}

pub fn encode_url(content: &str) -> String {
    encode(content).into_owned()
}

#[cfg(test)]
mod tests {

    use crate::url_encode::encode_url_path;

    #[test]
    fn preserve_slash() {
        assert_eq!(&encode_url_path("/path/"), "/path/");
    }

    #[test]
    fn encode_plus() {
        assert_eq!(&encode_url_path("/path+/"), "/path%2B/");
    }

    #[test]
    fn encode_asterisk() {
        assert_eq!(&encode_url_path("/path*/"), "/path%2A/");
    }

    #[test]
    fn encode_tiled_operator() {
        assert_eq!(&encode_url_path("/path~/"), "/path~/");
    }
}

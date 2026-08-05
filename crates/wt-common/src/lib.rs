pub fn placeholder() -> u32 {
    42
}

#[cfg(test)]
mod tests {
    #[test]
    fn placeholder_works() {
        assert_eq!(super::placeholder(), 42);
    }
}

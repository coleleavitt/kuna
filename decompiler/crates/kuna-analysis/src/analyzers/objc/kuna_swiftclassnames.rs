//! (kuna) The one place an Objective-C runtime class name becomes the name
//! kuna shows: a Swift class registers with the runtime as `_TtC6Toyota3Foo`,
//! and under `swiftdemangle` every rendering of it — method labels, the
//! instance struct, `@"…"` pointer types, ivar offset symbols — says
//! `Toyota.Foo`. Lookups between the ObjC tables keep the runtime spelling.

/// The class name kuna renders: the Swift demangling of an ObjC runtime name
/// (`_TtC6Toyota3Foo` → `Toyota.Foo`) when `swiftdemangle` is on and the name
/// is in the demangler's coverage, else the runtime spelling as is.
pub fn display_class_name(runtime_name: &str) -> String {
    if is_swift_runtime_name(runtime_name) && kuna_decomp::kuna_swiftdemangle::swiftdemangle_enabled() {
        if let Some(d) = crate::demangle::kuna_swift::demangle_swift_name(runtime_name) {
            return d;
        }
    }
    runtime_name.to_string()
}

/// A class the Swift compiler registered with the ObjC runtime.
pub fn is_swift_runtime_name(runtime_name: &str) -> bool {
    runtime_name.starts_with("_Tt")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn swift_runtime_class_names_demangle_for_labels() {
        assert_eq!(display_class_name("Greeter"), "Greeter");
        assert_eq!(display_class_name("_TtC6Toyota24AddMileageViewController"), "Toyota.AddMileageViewController");
        assert_eq!(display_class_name("_TtCC6Toyota5Outer5Inner"), "Toyota.Outer.Inner");
        // Outside the demangler's coverage the runtime spelling stays.
        assert_eq!(display_class_name("_TtC1"), "_TtC1");
    }
}

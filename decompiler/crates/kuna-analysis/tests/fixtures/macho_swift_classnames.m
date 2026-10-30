// Self-contained Mach-O fixture for Swift runtime class names in types
// (`swiftdemangle` + `objcivars`, tests/stages/kuna-swiftclassnames.xml). No
// Swift toolchain is needed: `objc_runtime_name` gives each class the name
// swiftc registers for `main.Engine` / `main.Car`, so the instance struct, the
// embedded superclass, the `@"_TtC4main6Engine"` ivar type and the typed
// `self` all go through the runtime-to-shown name mapping. `-x` strips local
// symbols so only the `__objc_*` metadata names anything. See
// fixtures/README.md ("Mach-O Swift class names") for the build recipe.
__attribute__((objc_root_class))
__attribute__((objc_runtime_name("_TtC4main7Vehicle")))
@interface Vehicle { long wheels; } @end
@implementation Vehicle @end
__attribute__((objc_root_class))
__attribute__((objc_runtime_name("_TtC4main6Engine")))
@interface Engine { double displacement; int cylinders; } @end
@implementation Engine
- (double)perCylinder { return displacement / cylinders; }
@end
__attribute__((objc_runtime_name("_TtC4main3Car")))
@interface Car : Vehicle { Engine *engine; long seats; } @end
@implementation Car
- (double)loadPerSeat:(long)load { return (double)(load + wheels) / seats + [engine perCylinder]; }
@end
int main(void) { return 0; }

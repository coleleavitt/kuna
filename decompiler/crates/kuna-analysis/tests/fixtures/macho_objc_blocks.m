// Self-contained Mach-O fixture for stack blocks (tests/stages/kuna-objcblocks.xml):
// `-[Runner maker:]` builds a block literal on its frame (`_NSConcreteStackBlock`
// isa, the invoke and descriptor addresses stored after it) and sends it; the
// invoke function is a stripped local symbol. See fixtures/README.md
// ("Mach-O stack blocks") for the build recipe.
__attribute__((objc_root_class))
@interface Runner { long base; }
- (long)run:(long)v with:(long (^)(long))b;
- (long)maker:(long)k;
@end
@implementation Runner
- (long)run:(long)v with:(long (^)(long))b { return b(v) + base; }
- (long)maker:(long)k { long c = base + k; return [self run:k with:^long(long x) { return x * c; }]; }
@end
int main(void) { return 0; }

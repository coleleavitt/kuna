// Self-contained Objective-C Mach-O fixture for variadic selectors in the
// `objcsdk` header reader: `Fmt` is declared but never implemented here, so
// each send goes through an `objc_msgSend$<sel>` stub that only the header
// describes. Root class, so it needs no macOS SDK.
__attribute__((objc_root_class)) @interface Fmt
+ (id)stringWithFormat:(id)format, ...;
- (void)logLevel:(long)level format:(const char *)format, ...;
@end
id describe(Fmt *log, const char *name, long count) {
  [log logLevel:2 format:"%s has %ld", name, count];
  return [Fmt stringWithFormat:(id)"%s=%ld", name, count];
}
int main(void) { return 0; }

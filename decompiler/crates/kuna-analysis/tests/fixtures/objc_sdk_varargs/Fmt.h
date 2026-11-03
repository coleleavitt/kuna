// A hand-written stand-in for an SDK framework header (no Apple text): two
// variadic method declarations, one with a format-attribute trailer. Read by
// the kuna_objcsdk unit tests and the kuna-objcsdkvarargs stage test.
#import <Foundation/Foundation.h>

typedef long NSInteger;

@interface Fmt : NSObject
+ (id)stringWithFormat:(NSString *)format, ... NS_FORMAT_FUNCTION(1,2);
- (void)logLevel:(NSInteger)level format:(const char *)format, ...;
- (void)logLevel:(NSInteger)level format:(const char *)format arguments:(va_list)args;
@end

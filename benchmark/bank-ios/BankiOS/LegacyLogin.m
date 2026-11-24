#import <Foundation/Foundation.h>

@interface LegacyLogin : NSObject
- (void)rememberPassword:(NSString *)password;
@end

@implementation LegacyLogin

- (void)rememberPassword:(NSString *)password {
    [[NSUserDefaults standardUserDefaults] setObject:password forKey:@"savedPassword"];
}

@end

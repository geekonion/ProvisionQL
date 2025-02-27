#include <CoreFoundation/CoreFoundation.h>
#include <CoreServices/CoreServices.h>
#include <QuickLook/QuickLook.h>

#import <Foundation/Foundation.h>
#import <Cocoa/Cocoa.h>
#import <Security/Security.h>

#import "NSBezierPath+IOS7RoundedRect.h"

static NSString * const kPluginBundleId = @"com.ealeksandrov.ProvisionQL";
static NSString * const kDataType_ipa               = @"com.apple.itunes.ipa";
static NSString * const kDataType_app               = @"com.apple.application-bundle";
static NSString * const kDataType_app2              = @"com.apple.application-file";
static NSString * const kDataType_framework         = @"com.apple.framework";
static NSString * const kDataType_dylib             = @"com.apple.mach-o-dylib";
static NSString * const kDataType_ios_provision     = @"com.apple.mobileprovision";
static NSString * const kDataType_ios_provision_old = @"com.apple.iphone.mobileprovision";
static NSString * const kDataType_osx_provision     = @"com.apple.provisionprofile";
static NSString * const kDataType_xcode_archive     = @"com.apple.xcode.archive";
static NSString * const kDataType_app_extension     = @"com.apple.application-and-system-extension";
static NSString * const kDataType_metadata_importer = @"com.apple.metadata-importer";
static NSString * const kDataType_public_folder     = @"public.folder";
static NSString * const kDataType_sim_device        = @"com.apple.coresimulator.simdevicetype";
static NSString * const kDataType_xpc_service       = @"com.apple.xpc-service";
static NSString * const kDataType_plugin            = @"com.apple.plugin";
static NSString * const kDataType_ide_plugin        = @"com.apple.dt.ide.plug-in";
static NSString * const kDataType_dvt_plugin        = @"com.apple.dt.dvt.plug-in";
static NSString * const kDataType_generic_bundle    = @"com.apple.generic-bundle";

// 3rd party ipa-like file extensions
static NSString * _Nonnull const kDataType_trollstore_ipa     = @"com.opa334.trollstore.tipa";
static NSString * _Nonnull const kDataType_trollstore_ipa_dyn = @"dyn.ah62d4rv4ge81k4puqe";

NSData *unzipFile(NSURL *url, NSString *filePath);
BOOL unzipFileToDir(NSURL *url, NSString *filePath, NSString *targetDir);

NSImage *roundCorners(NSImage *image);
NSImage *imageFromApp(NSURL *URL, NSString *dataType, NSString *fileName);
NSString *mainIconNameForApp(NSDictionary *appPropertyList);
int expirationStatus(NSDate *date, NSCalendar *calendar);

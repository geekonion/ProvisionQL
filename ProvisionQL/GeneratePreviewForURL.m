#import "Shared.h"
#import "NSBundle+ProvisionQL.h"
#import <Security/Security.h>

OSStatus GeneratePreviewForURL(void *thisInterface, QLPreviewRequestRef preview, CFURLRef url, CFStringRef contentTypeUTI, CFDictionaryRef options);
void CancelPreviewGeneration(void *thisInterface, QLPreviewRequestRef preview);

struct CS_Blob {
    uint32_t magic;                 // magic number
    uint32_t length;                // total length of blob
};

enum {
    kSecCodeMagicEntitlement = 0xfade7171,        /* entitlements blob */
    kSecCodeMagicEntitlementDER = 0xfade7172,   /* entitlements der https://pkg.go.dev/github.com/blacktop/go-macho/types/codesign */
};
/* -----------------------------------------------------------------------------
 Generate a preview for file
 
 This function's job is to create preview for designated file
 ----------------------------------------------------------------------------- */

void displayKeyAndValue(NSUInteger level, NSString *key, id value, NSMutableString *output) {
    int indent = (int)(level * 4);

    if ([value isKindOfClass:[NSDictionary class]]) {
        if (key) {
            [output appendFormat:@"%*s%@ = {\n", indent, "", key];
        } else if (level != 0) {
            [output appendFormat:@"%*s{\n", indent, ""];
        }
        NSDictionary *dictionary = (NSDictionary *)value;
        [dictionary enumerateKeysAndObjectsUsingBlock:^(id  _Nonnull subKey, id  _Nonnull obj, BOOL * _Nonnull stop) {
            NSUInteger subLevel = (key == nil && level == 0) ? 0 : level + 1;
            displayKeyAndValue(subLevel, subKey, obj, output);
        }];
        [output appendFormat:@"%*s}\n", indent, ""];
    } else if ([value isKindOfClass:[NSArray class]]) {
        [output appendFormat:@"%*s%@ = (\n", indent, "", key];
        NSArray *array = (NSArray *)value;
        for (id value in array) {
            displayKeyAndValue(level + 1, nil, value, output);
        }
        [output appendFormat:@"%*s)\n", indent, ""];
    } else if ([value isKindOfClass:[NSData class]]) {
        NSData *data = (NSData *)value;
        const char *bytes = data.bytes;
        struct CS_Blob *ent = (void *)bytes;
        if (ent && _OSSwapInt32(ent->magic) == kSecCodeMagicEntitlement) {
            uint32_t header_len = sizeof(struct CS_Blob);
            uint32_t length = _OSSwapInt32(ent->length) - header_len;
            NSString *ent = [[NSString alloc] initWithBytes:bytes + header_len length:length encoding:NSUTF8StringEncoding];
            [output appendString:ent];
        } else {
            if (key) {
                [output appendFormat:@"%*s%@ = %zd bytes of data\n", indent, "", key, [data length]];
            } else {
                [output appendFormat:@"%*s%zd bytes of data\n", indent, "", [data length]];
            }
        }
    } else {
        if (key) {
            [output appendFormat:@"%*s%@ = %@\n", indent, "", key, value];
        } else {
            [output appendFormat:@"%*s%@\n", indent, "", value];
        }
    }
}

NSString *expirationStringForDateInCalendar(NSDate *date, NSCalendar *calendar) {
    NSString *result = nil;

    if (date) {
        NSDateComponentsFormatter *formatter = [[NSDateComponentsFormatter alloc] init];
        formatter.unitsStyle = NSDateComponentsFormatterUnitsStyleFull;
        formatter.maximumUnitCount = 1;

        NSDateComponents *dateComponents = [calendar components:(NSCalendarUnitDay|NSCalendarUnitHour|NSCalendarUnitMinute)
                                                       fromDate:[NSDate date]
                                                         toDate:date
                                                        options:0];
        if ([date compare:[NSDate date]] == NSOrderedAscending) {
            if ([calendar isDate:date inSameDayAsDate:[NSDate date]]) {
                result = @"<span>Expired today</span>";
            } else {
                NSDateComponents *reverseDateComponents = [calendar components:(NSCalendarUnitDay|NSCalendarUnitHour|NSCalendarUnitMinute)
                                                                      fromDate:date
                                                                        toDate:[NSDate date]
                                                                       options:0];
                result = [NSString stringWithFormat:@"<span>Expired %@ ago</span>", [formatter stringFromDateComponents:reverseDateComponents]];
            }
        } else {
            if (dateComponents.day == 0) {
                result = @"<span>Expires today</span>";
            } else if (dateComponents.day < 30) {
                result = [NSString stringWithFormat:@"<span>Expires in %@</span>", [formatter stringFromDateComponents:dateComponents]];
            } else {
                result = [NSString stringWithFormat:@"Expires in %@", [formatter stringFromDateComponents:dateComponents]];
            }
        }

    }

    return result;
}

NSString *formattedStringForCertificates(NSArray *value) {
    static NSString *const devCertSummaryKey = @"summary";
    static NSString *const devCertInvalidityDateKey = @"invalidity";

    NSMutableArray *certificateDetails = [NSMutableArray array];
    NSArray *array = (NSArray *)value;
    for (NSData *data in array) {
        SecCertificateRef certificateRef = SecCertificateCreateWithData(NULL, (__bridge CFDataRef)data);
        if (certificateRef) {
            CFStringRef summaryRef = SecCertificateCopySubjectSummary(certificateRef);
            NSString *summary = (NSString *)CFBridgingRelease(summaryRef);
            if (summary) {
                NSMutableDictionary *detailsDict = [NSMutableDictionary dictionaryWithObject:summary forKey:devCertSummaryKey];

                CFErrorRef error;
                CFDictionaryRef valuesDict = SecCertificateCopyValues(certificateRef, (__bridge CFArrayRef)@[(__bridge id)kSecOIDInvalidityDate], &error);
                if (valuesDict) {
                    CFDictionaryRef invalidityDateDictionaryRef = CFDictionaryGetValue(valuesDict, kSecOIDInvalidityDate);
                    if (invalidityDateDictionaryRef) {
                        CFTypeRef invalidityRef = CFDictionaryGetValue(invalidityDateDictionaryRef, kSecPropertyKeyValue);
                        CFRetain(invalidityRef);

                        // NOTE: the invalidity date type of kSecPropertyTypeDate is documented as a CFStringRef in the "Certificate, Key, and Trust Services Reference".
                        // In reality, it's a __NSTaggedDate (presumably a tagged pointer representing an NSDate.) But to sure, we'll check:
                        id invalidity = CFBridgingRelease(invalidityRef);
                        if (invalidity) {
                            if ([invalidity isKindOfClass:[NSDate class]]) {
                                // use the date directly
                                [detailsDict setObject:invalidity forKey:devCertInvalidityDateKey];
                            } else {
                                // parse the date from a string
                                NSString *string = [invalidity description];
                                NSDateFormatter *invalidityDateFormatter = [NSDateFormatter new];
                                [invalidityDateFormatter setDateFormat:@"yyyy-MM-dd HH:mm:ss Z"];
                                NSDate *invalidityDate = [invalidityDateFormatter dateFromString:string];
                                if (invalidityDate) {
                                    [detailsDict setObject:invalidityDate forKey:devCertInvalidityDateKey];
                                }
                            }
                        } else {
                            NSLog(@"No invalidity date in '%@' certificate, dictionary = %@", summary, invalidityDateDictionaryRef);
                        }
                    } else {
                        NSLog(@"No invalidity values in '%@' certificate, dictionary = %@", summary, valuesDict);
                    }

                    CFRelease(valuesDict);
                } else {
                    NSLog(@"Could not get values in '%@' certificate, error = %@", summary, error);
                }

                [certificateDetails addObject:detailsDict];
            } else {
                NSLog(@"Could not get summary from certificate");
            }

            CFRelease(certificateRef);
        }
    }

    NSMutableString *certificates = [NSMutableString string];
    [certificates appendString:@"<table>\n"];

    NSArray *sortedCertificateDetails = [certificateDetails sortedArrayUsingComparator:^NSComparisonResult(id obj1, id obj2) {
        return [((NSDictionary *)obj1)[devCertSummaryKey] compare:((NSDictionary *)obj2)[devCertSummaryKey]];
    }];

    for (NSDictionary *detailsDict in sortedCertificateDetails) {
        NSString *summary = detailsDict[devCertSummaryKey];
        NSDate *invalidityDate = detailsDict[devCertInvalidityDateKey];
        NSString *expiration = expirationStringForDateInCalendar(invalidityDate, [NSCalendar currentCalendar]);
        if (! expiration) {
            expiration = @"<span class='warning'>No invalidity date in certificate</span>";
        }
        [certificates appendFormat:@"<tr><td>%@</td><td>%@</td></tr>\n", summary, expiration];
    }
    [certificates appendString:@"</table>\n"];

    return [certificates copy];
}

NSDictionary *formattedDevicesData(NSArray *value) {

    NSArray *array = (NSArray *)value;
    NSArray *sortedArray = [array sortedArrayUsingSelector:@selector(compare:)];

    NSString *currentPrefix = nil;
    NSMutableString *devices = [NSMutableString string];
    [devices appendString:@"<table>\n"];
    [devices appendString:@"<tr><th></th><th>UDID</th></tr>\n"];

    for (NSString *device in sortedArray) {
        // compute the prefix for the first column of the table
        NSString *displayPrefix = @"";
        NSString *devicePrefix = [device substringToIndex:1];
        if (! [currentPrefix isEqualToString:devicePrefix]) {
            currentPrefix = devicePrefix;
            displayPrefix = [NSString stringWithFormat:@"%@ ➞ ", devicePrefix];
        }

        [devices appendFormat:@"<tr><td>%@</td><td>%@</td></tr>\n", displayPrefix, device];
    }
    [devices appendString:@"</table>\n"];

    return @{@"ProvisionedDevicesFormatted" : [devices copy], @"ProvisionedDevicesCount" : [NSString stringWithFormat:@"%zd Device%s", [array count], ([array count] == 1 ? "" : "s")]};
}

NSString *formattedDictionaryWithReplacements(NSDictionary *dictionary, NSDictionary *replacements, int level) {

    NSMutableString *string = [NSMutableString string];

    for (NSString *key in dictionary) {
        NSString *localizedKey = replacements[key] ?: key;
        NSObject *object = dictionary[key];

        for (int idx = 0; idx < level; idx++) {
            if (level == 1) {
                [string appendString:@"- "];
            } else {
                [string appendString:@"&nbsp;&nbsp;"];
            }
        }

        if ([object isKindOfClass:[NSDictionary class]]) {
            object = formattedDictionaryWithReplacements((NSDictionary *)object, replacements, level + 1);
            [string appendFormat:@"%@:<div class=\"list\">%@</div>", localizedKey, object];
        }
        else if ([object isKindOfClass:[NSNumber class]]) {
            object = [(NSNumber *)object boolValue] ? @"YES" : @"NO";
            [string appendFormat:@"%@: %@<br />", localizedKey, object];
        }
        else {
            [string appendFormat:@"%@: %@<br />", localizedKey, object];
        }
    }

    return string;
}

NSString *escapedXML(NSString *stringToEscape) {
    stringToEscape = [stringToEscape stringByReplacingOccurrencesOfString:@"&" withString:@"&amp;"];
    NSDictionary *htmlEntityReplacement = @{
                                            @"\"": @"&quot;",
                                            @"'": @"&apos;",
                                            @"<": @"&lt;",
                                            @">": @"&gt;",
                                            };
    for (NSString *key in [htmlEntityReplacement allKeys]) {
        NSString *replacement = [htmlEntityReplacement objectForKey:key];
        stringToEscape = [stringToEscape stringByReplacingOccurrencesOfString:key withString:replacement];
    }
    return stringToEscape;
}

NSDictionary *codesignInfoFromApp(NSString *basePath, NSString *bundleExecutable) {
    NSString *binaryPath = [basePath stringByAppendingPathComponent:bundleExecutable];
    NSURL *binaryURL = [NSURL fileURLWithPath:binaryPath];
    
    // Create a SecStaticCodeRef from the binary file
    SecStaticCodeRef staticCode = NULL;
    OSStatus status = SecStaticCodeCreateWithPath((__bridge CFURLRef)binaryURL, kSecCSDefaultFlags, &staticCode);
    if (status != errSecSuccess || !staticCode) {
        NSLog(@"Failed to create static code for binary: %@", binaryPath);
        return nil;
    }
    
    // Retrieve the signing information
    CFDictionaryRef signingInfo = NULL;
    status = SecCodeCopySigningInformation(staticCode, kSecCSSigningInformation, &signingInfo);
    CFRelease(staticCode); // Release static code reference now that we're done with it
    
    if (status != errSecSuccess || !signingInfo) {
        NSLog(@"Failed to retrieve signing information for binary: %@", binaryPath);
        return nil;
    }
    
    return CFBridgingRelease(signingInfo);
}

NSString *iconAsBase64(NSImage *appIcon) {
    if (!appIcon) {
        NSURL *iconURL = [[NSBundle pluginBundle] URLForResource:@"defaultIcon" withExtension:@"png"];
        appIcon = [[NSImage alloc] initWithContentsOfURL:iconURL];
    }
    appIcon = roundCorners(appIcon);
    NSData *imageData = [appIcon TIFFRepresentation];
    NSBitmapImageRep *imageRep = [NSBitmapImageRep imageRepWithData:imageData];
    imageData = [imageRep representationUsingType:NSBitmapImageFileTypePNG properties:@{}];
    return [imageData base64EncodedStringWithOptions:0];
}

NSData* generatePreviewDataForURL(NSURL *URL, NSString *dataType) {
    NSString *path = [URL absoluteString];
    if ([path hasPrefix:@"file:///.file/id="]) {
        URL = [URL filePathURL];
        path = [URL path];
    } else {
        path = [URL path];
    }
    
    unichar last = [path characterAtIndex:path.length - 1];
    if (last == '/') {
        path = [path substringToIndex:path.length - 1];
    }
    
    if ([dataType hasPrefix:@"dyn."]) {
        if ([path hasSuffix:@".appex"]) {
            dataType = kDataType_app_extension;
        } else if ([path hasSuffix:@".xcarchive"]) {
            dataType = kDataType_xcode_archive;
        } else if ([path hasSuffix:@".framework"]) {
            dataType = kDataType_framework;
        }
    }
    
    @autoreleasepool {
        NSFileManager *fileManager = [NSFileManager defaultManager];
        NSURL *targetURL = nil;
        NSData *provisionData = nil;
        NSData *appPlist = nil;
        NSDictionary *codesignInfo = nil;
        NSImage *appIcon = nil;
        NSString *title = nil;

        if ([dataType isEqualToString:kDataType_ipa]
            // for now, treat .tipa as if it were a normal .ipa file.
            || [dataType isEqualToString:kDataType_trollstore_ipa]
            || [dataType isEqualToString:kDataType_trollstore_ipa_dyn]) {
            title = @"App info";
            // create temp directory
            NSString *tempDirFolder = [NSTemporaryDirectory() stringByAppendingPathComponent:kPluginBundleId];
            NSString *currentTempDirFolder = [tempDirFolder stringByAppendingPathComponent:[[NSUUID UUID] UUIDString]];
            [fileManager createDirectoryAtPath:currentTempDirFolder withIntermediateDirectories:YES attributes:nil error:nil];
            
            provisionData = unzipFile(URL, @"Payload/*.app/embedded.mobileprovision");
            appPlist = unzipFile(URL, @"Payload/*.app/Info.plist");

            // read codesigning entitlements from application binary (extract it first)
            NSDictionary *appPropertyList = [NSPropertyListSerialization propertyListWithData:appPlist options:0 format:NULL error:NULL];
            NSString *bundleExecutable = [appPropertyList objectForKey:@"CFBundleExecutable"];

            unzipFileToDir(URL, currentTempDirFolder, [@"Payload/*.app/" stringByAppendingPathComponent:bundleExecutable]);

            codesignInfo = codesignInfoFromApp(currentTempDirFolder, bundleExecutable);

            [fileManager removeItemAtPath:tempDirFolder error:nil];
        } else if ([dataType isEqualToString:kDataType_app] || [dataType isEqualToString:kDataType_app2]) {
            title = @"App info";
            targetURL = URL;
        } else if ([dataType isEqualToString:kDataType_xcode_archive]) {
            title = @"Archive info";
            // get the embedded plist for the iOS app
            NSURL *appsDir = [URL URLByAppendingPathComponent:@"Products/Applications/"];
            if (appsDir != nil) {
                NSArray *dirFiles = [[NSFileManager defaultManager] contentsOfDirectoryAtPath:appsDir.path error:nil];
                if (dirFiles.count > 0) {
                    targetURL = [appsDir URLByAppendingPathComponent:dirFiles[0] isDirectory:YES];
                }
            }
        } else if ([dataType isEqualToString:kDataType_app_extension]) {
            title = @"App extension info";
            targetURL = URL;
        } else if ([dataType isEqualToString:kDataType_framework]) {
            title = @"Framework info";
            targetURL = URL;
        } else {
            title = @"Provision info";
            // use provisioning directly
            provisionData = [NSData dataWithContentsOfURL:URL];
        }
        
        if (targetURL) {
            // Mac App
            NSURL *contentsURL = [targetURL URLByAppendingPathComponent:@"Contents"];
            BOOL isMacApp = NO;
            isMacApp = [fileManager fileExistsAtPath:contentsURL.path];
            if (!isMacApp) {
                // Mac framework
                contentsURL = [targetURL URLByAppendingPathComponent:@"Resources"];
                isMacApp = [fileManager fileExistsAtPath:contentsURL.path];
            }
            NSURL *provisionURL = nil;
            NSURL *infoplistURL = nil;
            if (isMacApp) {
                infoplistURL = [contentsURL URLByAppendingPathComponent:@"Info.plist"];
            } else {
                provisionURL = [targetURL URLByAppendingPathComponent:@"embedded.mobileprovision"];
                infoplistURL = [targetURL URLByAppendingPathComponent:@"Info.plist"];
            }
            if (provisionURL)
                provisionData = [NSData dataWithContentsOfURL:provisionURL];
            appPlist = [NSData dataWithContentsOfURL:infoplistURL];
            if (appPlist) {
                NSDictionary *appPropertyList = [NSPropertyListSerialization propertyListWithData:appPlist options:0 format:NULL error:NULL];
                NSString *bundleExecutable = [appPropertyList objectForKey:@"CFBundleExecutable"];
                
                NSString *dir = targetURL.path;
                if (isMacApp && ([dataType isEqualToString:kDataType_app] || [dataType isEqualToString:kDataType_app2] || [dataType isEqualToString:kDataType_xcode_archive] || [dataType isEqualToString:kDataType_app_extension])) {
                    dir = [dir stringByAppendingPathComponent:@"Contents/MacOS"];
                }
                // read codesigning info from application binary
                codesignInfo = codesignInfoFromApp(dir, bundleExecutable);
            }
        }

        NSMutableDictionary *synthesizedInfo = [NSMutableDictionary dictionary];
        NSURL *htmlURL = [[NSBundle pluginBundle] URLForResource:@"template" withExtension:@"html"];
        NSMutableString *html = [NSMutableString stringWithContentsOfURL:htmlURL encoding:NSUTF8StringEncoding error:NULL];
        NSDateFormatter *dateFormatter = [NSDateFormatter new];
        [dateFormatter setDateStyle:NSDateFormatterMediumStyle];
        [dateFormatter setTimeStyle:NSDateFormatterMediumStyle];
        NSCalendar *calendar = [NSCalendar currentCalendar];
        id value = nil;
        NSString *synthesizedValue = nil;

        [synthesizedInfo setObject:title forKey:@"AppInfoTitle"];

        if (!provisionData) {
            NSLog(@"No provisionData for %@", URL);

            if (appPlist != nil || codesignInfo != nil) {
                [synthesizedInfo setObject:@"hiddenDiv" forKey:@"ProvisionInfo"];
            } else {
                return nil;
            }
        } else {
            [synthesizedInfo setObject:@"" forKey:@"ProvisionInfo"];
        }

        // MARK: App Info

        if (appPlist != nil) {
            NSDictionary *appPropertyList = [NSPropertyListSerialization propertyListWithData:appPlist options:0 format:NULL error:NULL];

            NSString *iconName = mainIconNameForApp(appPropertyList);
            appIcon = imageFromApp(URL, dataType, iconName);
            [synthesizedInfo setObject:iconAsBase64(appIcon) forKey:@"AppIcon"];

            NSString *bundleName = [appPropertyList objectForKey:@"CFBundleDisplayName"];
            if (!bundleName) {
                bundleName = [appPropertyList objectForKey:@"CFBundleName"];
            }
            [synthesizedInfo setObject:bundleName ?: @"" forKey:@"CFBundleName"];
            [synthesizedInfo setObject:[appPropertyList objectForKey:@"CFBundleIdentifier"] ?: @"" forKey:@"CFBundleIdentifier"];
            [synthesizedInfo setObject:[appPropertyList objectForKey:@"CFBundleShortVersionString"] ?: @"" forKey:@"CFBundleShortVersionString"];
            [synthesizedInfo setObject:[appPropertyList objectForKey:@"CFBundleVersion"] ?: @"" forKey:@"CFBundleVersion"];

            NSString *extensionType = [[appPropertyList objectForKey:@"NSExtension"] objectForKey:@"NSExtensionPointIdentifier"];
            if(extensionType != nil) {
                [synthesizedInfo setObject:@"" forKey:@"ExtensionInfo"];
                [synthesizedInfo setObject:extensionType forKey:@"NSExtensionPointIdentifier"];
            } else {
                [synthesizedInfo setObject:@"hiddenDiv" forKey:@"ExtensionInfo"];
            }
            
            NSString *exeName = [appPropertyList objectForKey:@"CFBundleExecutable"] ?: @"";
            [synthesizedInfo setObject:exeName forKey:@"CFBundleExecutable"];
            
            NSString *DTXcode = [appPropertyList objectForKey:@"DTXcode"] ?: @"";
            [synthesizedInfo setObject:DTXcode forKey:@"DTXcode"];

            NSString *sdkName = [appPropertyList objectForKey:@"DTSDKName"] ?: @"";
            [synthesizedInfo setObject:sdkName forKey:@"DTSDKName"];

            NSString *minimumOSVersion = [appPropertyList objectForKey:@"MinimumOSVersion"] ?: @"";
            [synthesizedInfo setObject:minimumOSVersion forKey:@"MinimumOSVersion"];

            NSDictionary *appTransportSecurity = [appPropertyList objectForKey:@"NSAppTransportSecurity"];
            NSString *appTransportSecurityFormatted = @"No exceptions";
            if ([appTransportSecurity isKindOfClass:[NSDictionary class]]) {
                NSDictionary *localizedKeys = @{
                                                @"NSAllowsArbitraryLoads": @"Allows Arbitrary Loads",
                                                @"NSAllowsArbitraryLoadsForMedia": @"Allows Arbitrary Loads for Media",
                                                @"NSAllowsArbitraryLoadsInWebContent": @"Allows Arbitrary Loads in Web Content",
                                                @"NSAllowsLocalNetworking": @"Allows Local Networking",
                                                @"NSExceptionDomains": @"Exception Domains",

                                                @"NSIncludesSubdomains": @"Includes Subdomains",
                                                @"NSRequiresCertificateTransparency": @"Requires Certificate Transparency",

                                                @"NSExceptionAllowsInsecureHTTPLoads": @"Allows Insecure HTTP Loads",
                                                @"NSExceptionMinimumTLSVersion": @"Minimum TLS Version",
                                                @"NSExceptionRequiresForwardSecrecy": @"Requires Forward Secrecy",

                                                @"NSThirdPartyExceptionAllowsInsecureHTTPLoads": @"Allows Insecure HTTP Loads",
                                                @"NSThirdPartyExceptionMinimumTLSVersion": @"Minimum TLS Version",
                                                @"NSThirdPartyExceptionRequiresForwardSecrecy": @"Requires Forward Secrecy"
                                                };

                NSString *formattedDictionaryString = formattedDictionaryWithReplacements(appTransportSecurity, localizedKeys, 0);
                appTransportSecurityFormatted = [NSString stringWithFormat:@"<div class=\"list\">%@</div>", formattedDictionaryString];
            } else {
                double sdkNumber = [[sdkName stringByTrimmingCharactersInSet:[NSCharacterSet letterCharacterSet]] doubleValue];
                if (sdkNumber < 9.0) {
                    appTransportSecurityFormatted = @"Not applicable before iOS 9.0";
                }
            }

            [synthesizedInfo setObject:appTransportSecurityFormatted forKey:@"AppTransportSecurityFormatted"];
            
            NSMutableArray *platforms = [NSMutableArray array];
            for (NSNumber *number in [appPropertyList objectForKey:@"UIDeviceFamily"]) {
                switch ([number intValue]) {
                    case 1:
                        [platforms addObject:@"iPhone"];
                        break;
                    case 2:
                        [platforms addObject:@"iPad"];
                        break;
                    case 3:
                        [platforms addObject:@"TV"];
                        break;
                    case 4:
                        [platforms addObject:@"Watch"];
                        break;
                    default:
                        break;
                }
            }
            [synthesizedInfo setObject:[platforms componentsJoinedByString:@", "] forKey:@"UIDeviceFamily"];
            [synthesizedInfo setObject:@"" forKey:@"AppInfo"];
            [synthesizedInfo setObject:@"hiddenDiv" forKey:@"ProvisionAsSubheader"];
        } else {
            [synthesizedInfo setObject:@"hiddenDiv" forKey:@"AppInfo"];
            [synthesizedInfo setObject:@"" forKey:@"ProvisionAsSubheader"];
        }

        // MARK: Provisioning
        NSData *data = nil;
        if (provisionData) {
            CMSDecoderRef decoder = NULL;
            CMSDecoderCreate(&decoder);
            CMSDecoderUpdateMessage(decoder, provisionData.bytes, provisionData.length);
            CMSDecoderFinalizeMessage(decoder);
            CFDataRef dataRef = NULL;
            CMSDecoderCopyContent(decoder, &dataRef);
            data = (NSData *)CFBridgingRelease(dataRef);
            CFRelease(decoder);
        }

        if ((!data && !appPlist && !codesignInfo)) {
            return nil;
        }

        if (data) {
            // use all keys and values in the property list to generate replacement tokens and values
            NSDictionary *propertyList = [NSPropertyListSerialization propertyListWithData:data options:0 format:NULL error:NULL];
            for (NSString *key in [propertyList allKeys]) {
                NSString *replacementValue = [[propertyList valueForKey:key] description];
                NSString *replacementToken = [NSString stringWithFormat:@"__%@__", key];
                [html replaceOccurrencesOfString:replacementToken withString:replacementValue options:0 range:NSMakeRange(0, [html length])];
            }

            // synthesize other replacement tokens and values
            value = [propertyList objectForKey:@"CreationDate"];
            if ([value isKindOfClass:[NSDate class]]) {
                NSDate *date = (NSDate *)value;
                synthesizedValue = [dateFormatter stringFromDate:date];
                [synthesizedInfo setObject:synthesizedValue forKey:@"CreationDateFormatted"];

                NSDateComponents *dateComponents = [calendar components:(NSCalendarUnitDay|NSCalendarUnitHour|NSCalendarUnitMinute)
                                                               fromDate:date
                                                                 toDate:[NSDate date]
                                                                options:0];
                if ([calendar isDate:date inSameDayAsDate:[NSDate date]]) {
                    synthesizedValue = @"Created today";
                } else {
                    NSDateComponentsFormatter *formatter = [[NSDateComponentsFormatter alloc] init];
                    formatter.unitsStyle = NSDateComponentsFormatterUnitsStyleFull;
                    formatter.maximumUnitCount = 1;

                    synthesizedValue = [NSString stringWithFormat:@"Created %@ ago", [formatter stringFromDateComponents:dateComponents]];
                }
                [synthesizedInfo setObject:synthesizedValue forKey:@"CreationSummary"];
            }

            value = [propertyList objectForKey:@"ExpirationDate"];
            if ([value isKindOfClass:[NSDate class]]) {
                NSDate *date = (NSDate *)value;
                synthesizedValue = [dateFormatter stringFromDate:date];
                [synthesizedInfo setObject:synthesizedValue forKey:@"ExpirationDateFormatted"];

                synthesizedValue = expirationStringForDateInCalendar(date, calendar);
                [synthesizedInfo setObject:synthesizedValue forKey:@"ExpirationSummary"];

                int expStatus = expirationStatus(date, calendar);
                if (expStatus == 0) {
                    synthesizedValue = @"expired";
                } else if (expStatus == 1) {
                    synthesizedValue = @"expiring";
                } else {
                    synthesizedValue = @"valid";
                }
                [synthesizedInfo setObject:synthesizedValue forKey:@"ExpStatus"];
            }

            value = [propertyList objectForKey:@"TeamIdentifier"];
            if ([value isKindOfClass:[NSArray class]]) {
                NSArray *array = (NSArray *)value;
                synthesizedValue = [array componentsJoinedByString:@", "];
                [synthesizedInfo setObject:synthesizedValue forKey:@"TeamIds"];
            }

            // read the entitlements from the provisioning profile instead
            value = [propertyList objectForKey:@"Entitlements"];
            if ([value isKindOfClass:[NSDictionary class]]) {
                NSDictionary *dictionary = (NSDictionary *)value;
                NSMutableString *dictionaryFormatted = [NSMutableString string];
                displayKeyAndValue(0, nil, dictionary, dictionaryFormatted);
                synthesizedValue = [NSString stringWithFormat:@"<pre>%@</pre>", dictionaryFormatted];
                
                [synthesizedInfo setObject:synthesizedValue forKey:@"EntitlementsFormatted"];
            } else {
                [synthesizedInfo setObject:@"No Entitlements" forKey:@"EntitlementsFormatted"];
            }

            value = [propertyList objectForKey:@"DeveloperCertificates"];
            if ([value isKindOfClass:[NSArray class]]) {
                [synthesizedInfo setObject:formattedStringForCertificates(value) forKey:@"DeveloperCertificatesFormatted"];
            } else {
                [synthesizedInfo setObject:@"No Developer Certificates" forKey:@"DeveloperCertificatesFormatted"];
            }

            value = [propertyList objectForKey:@"ProvisionedDevices"];
            if ([value isKindOfClass:[NSArray class]]) {
                [synthesizedInfo addEntriesFromDictionary:formattedDevicesData(value)];
            } else {
                [synthesizedInfo setObject:@"No Devices" forKey:@"ProvisionedDevicesFormatted"];
                [synthesizedInfo setObject:@"Distribution Profile" forKey:@"ProvisionedDevicesCount"];
            }

            {
                NSString *profileString = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                profileString = escapedXML(profileString);
                synthesizedValue = [NSString stringWithFormat:@"<pre>%@</pre>", profileString];
                [synthesizedInfo setObject:synthesizedValue forKey:@"RawData"];
            }

            // older provisioning files don't include some key/value pairs
            value = [propertyList objectForKey:@"TeamName"];
            if (! value) {
                [synthesizedInfo setObject:@"<em>Team name not available</em>" forKey:@"TeamName"];
            }
            value = [propertyList objectForKey:@"TeamIdentifier"];
            if (! value) {
                [synthesizedInfo setObject:@"<em>Team ID not available</em>" forKey:@"TeamIds"];
            }
            value = [propertyList objectForKey:@"AppIDName"];
            if (! value) {
                [synthesizedInfo setObject:@"<em>App name not available</em>" forKey:@"AppIDName"];
            }

            // determine the profile type
            BOOL getTaskAllow = NO;
            value = [propertyList objectForKey:@"Entitlements"];
            if ([value isKindOfClass:[NSDictionary class]]) {
                NSDictionary *dictionary = (NSDictionary *)value;
                getTaskAllow = [[dictionary valueForKey:@"get-task-allow"] boolValue];
            }

            BOOL hasDevices = NO;
            value = [propertyList objectForKey:@"ProvisionedDevices"];
            if ([value isKindOfClass:[NSArray class]]) {
                hasDevices = YES;
            }

            BOOL isEnterprise = [[propertyList objectForKey:@"ProvisionsAllDevices"] boolValue];

            if ([dataType isEqualToString:kDataType_osx_provision]) {
                [synthesizedInfo setObject:@"mac" forKey:@"Platform"];

                [synthesizedInfo setObject:@"Mac" forKey:@"ProfilePlatform"];
                if (hasDevices) {
                    [synthesizedInfo setObject:@"Development" forKey:@"ProfileType"];
                } else {
                    [synthesizedInfo setObject:@"Distribution (App Store)" forKey:@"ProfileType"];
                }
            } else {
                [synthesizedInfo setObject:@"ios" forKey:@"Platform"];

                [synthesizedInfo setObject:@"iOS" forKey:@"ProfilePlatform"];
                if (hasDevices) {
                    if (getTaskAllow) {
                        [synthesizedInfo setObject:@"Development" forKey:@"ProfileType"];
                    } else {
                        [synthesizedInfo setObject:@"Distribution (Ad Hoc)" forKey:@"ProfileType"];
                    }
                } else {
                    if (isEnterprise) {
                        [synthesizedInfo setObject:@"Enterprise" forKey:@"ProfileType"];
                    } else {
                        [synthesizedInfo setObject:@"Distribution (App Store)" forKey:@"ProfileType"];
                    }
                }
            }
        }
        
        // 没有provision时，显示二进制文件中获取到的entitlements
        if (codesignInfo.count) {
            synthesizedValue = [NSString stringWithFormat:@"<pre>%@</pre>", codesignInfo];
            
            [synthesizedInfo setObject:synthesizedValue forKey:@"SignInfoFormatted"];
        } else {
            [synthesizedInfo setObject:@"No signing info" forKey:@"SignInfoFormatted"];
        }

        // MARK: File Info
        
        [synthesizedInfo setObject:escapedXML([URL lastPathComponent]) forKey:@"FileName"];

        if ([[URL pathExtension] isEqualToString:@"app"] || [[URL pathExtension] isEqualToString:@"appex"]) {
            // get the "file" information using the application package folder
            NSString *folderPath = [URL path];

            NSDictionary *folderAttributes = [fileManager attributesOfItemAtPath:folderPath error:NULL];
            if (folderAttributes) {
                NSDate *folderModificationDate = [folderAttributes fileModificationDate];

                unsigned long long folderSize = 0;
                NSArray *filesArray = [fileManager subpathsOfDirectoryAtPath:folderPath error:nil];
                for (NSString *fileName in filesArray) {
                    NSDictionary *fileAttributes = [fileManager attributesOfItemAtPath:[folderPath stringByAppendingPathComponent:fileName] error:NULL];
                    if (fileAttributes)
                    folderSize += [fileAttributes fileSize];
                }

                synthesizedValue = [NSString stringWithFormat:@"%@, Modified %@",
                                    [NSByteCountFormatter stringFromByteCount:folderSize countStyle:NSByteCountFormatterCountStyleFile],
                                    [dateFormatter stringFromDate:folderModificationDate]];
                [synthesizedInfo setObject:synthesizedValue forKey:@"FileInfo"];
            } else {
                [synthesizedInfo setObject:@"" forKey:@"FileInfo"];
            }
        } else {
            NSDictionary *fileAttributes = [fileManager attributesOfItemAtPath:[URL path] error:NULL];
            if (fileAttributes) {
                NSDate *fileModificationDate = [fileAttributes fileModificationDate];
                unsigned long long fileSize = [fileAttributes fileSize];
                
                synthesizedValue = [NSString stringWithFormat:@"%@, Modified %@",
                                    [NSByteCountFormatter stringFromByteCount:fileSize countStyle:NSByteCountFormatterCountStyleFile],
                                    [dateFormatter stringFromDate:fileModificationDate]];
                [synthesizedInfo setObject:synthesizedValue forKey:@"FileInfo"];
            }
        }

        // MARK: Footer

#ifdef DEBUG
        [synthesizedInfo setObject:@"(debug)" forKey:@"DEBUG"];
#else
        [synthesizedInfo setObject:@"" forKey:@"DEBUG"];
#endif

        synthesizedValue = [[NSBundle pluginBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"];
        [synthesizedInfo setObject:synthesizedValue ?: @"" forKey:@"BundleShortVersionString"];

        synthesizedValue = [[NSBundle pluginBundle] objectForInfoDictionaryKey:@"CFBundleVersion"];
        [synthesizedInfo setObject:synthesizedValue ?: @"" forKey:@"BundleVersion"];

        for (NSString *key in [synthesizedInfo allKeys]) {
            NSString *replacementValue = [synthesizedInfo objectForKey:key];
            NSString *replacementToken = [NSString stringWithFormat:@"__%@__", key];
            [html replaceOccurrencesOfString:replacementToken withString:replacementValue options:0 range:NSMakeRange(0, [html length])];
        }

        return [html dataUsingEncoding:NSUTF8StringEncoding];
    }

    return nil;
}

OSStatus GeneratePreviewForURL(void *thisInterface, QLPreviewRequestRef preview, CFURLRef url, CFStringRef contentTypeUTI, CFDictionaryRef options) {
    NSURL *URL = (__bridge NSURL *)url;
    NSString *dataType = (__bridge NSString *)contentTypeUTI;
    NSData *data = generatePreviewDataForURL(URL, dataType);
    
    if(data == nil || QLPreviewRequestIsCancelled(preview)) {
        NSDictionary *properties = @{ // properties for the HTML data
                                     (__bridge NSString *)kQLPreviewPropertyTextEncodingNameKey : @"UTF-8",
                                     (__bridge NSString *)kQLPreviewPropertyMIMETypeKey : @"text/html" };
        QLPreviewRequestSetDataRepresentation(preview, (__bridge CFDataRef)data, kUTTypeHTML, (__bridge CFDictionaryRef)properties);
    }

    return noErr;
}

void CancelThumbnailGeneration(void *thisInterface, QLThumbnailRequestRef thumbnail) {
    // Implement only if supported
}

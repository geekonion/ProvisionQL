//
//  ViewController.m
//  ProvisionQLApp
//
//  Created by Daniel Muhra on 31.10.24.
//  Copyright © 2024 Evgeny Aleksandrov. All rights reserved.
//

#import "ViewController.h"

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];

    CGSize size = self.view.bounds.size;
    CGFloat height = 30;
    CGFloat y = (size.height - height) / 2;
    NSRect rect = NSMakeRect(0, y, size.width, height);
    NSText *text = [[NSText alloc] initWithFrame:rect];
    text.string = @"选中需要预览的文件，按空格即可";
    text.font = [NSFont systemFontOfSize:25];
    text.alignment = NSTextAlignmentCenter;
    text.editable = NO;
    
    [self.view addSubview:text];
    self.view.wantsLayer = YES;
    self.view.layer.backgroundColor = [NSColor whiteColor].CGColor;
}


- (void)setRepresentedObject:(id)representedObject {
    [super setRepresentedObject:representedObject];

    // Update the view, if already loaded.
}


@end

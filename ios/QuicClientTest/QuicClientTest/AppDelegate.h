//
//  AppDelegate.h
//  QuicClientTest
//
//  Created by Chi Zhang on 2018/7/18.
//  Copyright © 2018年 Chi Zhang. All rights reserved.
//

#import <UIKit/UIKit.h>
#import <CoreData/CoreData.h>

@interface AppDelegate : UIResponder <UIApplicationDelegate>

@property (strong, nonatomic) UIWindow *window;

@property (readonly, strong) NSPersistentContainer *persistentContainer;

- (void)saveContext;


@end


package com.mycompany.impl;

import org.osgi.service.component.annotations.Component;

/**
 * Invalid service implementation that provides a service NOT matching the namespace pattern.
 * This should trigger a validation error.
 */
@Component(service = Runnable.class)
public class MyInvalidServiceImpl implements Runnable {
    
    @Override
    public void run() {
        // This component provides java.lang.Runnable which doesn't match com.mycompany.* pattern
    }
}
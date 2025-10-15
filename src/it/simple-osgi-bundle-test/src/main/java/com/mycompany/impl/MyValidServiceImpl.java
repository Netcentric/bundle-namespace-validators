package com.mycompany.impl;

import com.mycompany.api.MyValidService;
import org.osgi.service.component.annotations.Component;

/**
 * Valid service implementation that provides a service matching the namespace pattern.
 */
@Component(service = MyValidService.class)
public class MyValidServiceImpl implements MyValidService {
    
    @Override
    public String getMessage() {
        return "Hello from valid service";
    }
}

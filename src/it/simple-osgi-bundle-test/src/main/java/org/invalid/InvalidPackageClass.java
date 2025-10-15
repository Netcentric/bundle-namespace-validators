package org.invalid;

/**
 * This class is in a package that violates the namespace pattern.
 * It should trigger an export package validation error.
 */
public class InvalidPackageClass {
    
    /**
     * A simple method in an invalid package.
     */
    public void doSomething() {
        // This package doesn't match the com.mycompany.* pattern
    }
}
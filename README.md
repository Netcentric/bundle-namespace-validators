# Bundle Namespace Validators Bnd Plugin

[![Build Status](https://img.shields.io/github/actions/workflow/status/Netcentric/bundle-namespace-validators/maven.yml?branch=main)](https://github.com/Netcentric/bundle-namespace-validators/actions)
[![License](https://img.shields.io/badge/License-EPL%202.0-red.svg)](https://opensource.org/licenses/EPL-2.0)
[![Maven Central](https://img.shields.io/maven-central/v/biz.netcentric.osgi.bnd/bundle-namespace-validators)](https://central.sonatype.com/artifact/biz.netcentric.osgi.bnd/bundle-namespace-validators)
[![SonarCloud Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=Netcentric_bundle-namespace-validators&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=Netcentric_bundle-namespace-validators)
[![SonarCloud Coverage](https://sonarcloud.io/api/project_badges/measure?project=Netcentric_bundle-namespace-validators&metric=coverage)](https://sonarcloud.io/summary/new_code?id=Netcentric_bundle-namespace-validators)


## Overview

A [Bnd](https://bnd.bndtools.org/) plugin that validates OSGi bundle metadata compliance with configurable namespacing rules. This plugin helps ensure consistent naming conventions and organizational standards across OSGi bundles in enterprise projects. It validates the following aspects of an OSGi bundle

- **Export Package** - Validates that [exported packages](https://docs.osgi.org/specification/osgi.core/8.0.0/framework.module.html#framework.module.exportpackage) follow naming conventions
- **Bundle Symbolic Name** - Ensures [bundle symbolic names](https://docs.osgi.org/specification/osgi.core/8.0.0/framework.module.html#framework.module.bsn)  follow naming conventions
- **DS Component Provided Services** - Validates [provided service FQCNs in DS components](https://docs.osgi.org/specification/osgi.cmpn/8.1.0/service.component.html#service.component-service.element)
- **HTTP/Servlet Whiteboard** - Validates that HTTP servlets/filters registered via [HTTP/servlet whiteboard](https://docs.osgi.org/specification/osgi.cmpn/8.1.0/service.servlet.html) are listening to specific paths only
- **Sling Servlet/Filter** - Validates [Sling servlet](https://sling.apache.org/documentation/the-sling-engine/servlets.html) paths, resource types, and resource super types as well as [Sling filter](https://sling.apache.org/documentation/the-sling-engine/filters.html) patterns/resource types
- **Sling Authentication Handler** - Validates a [Sling Authentication Handler](https://sling.apache.org/documentation/the-sling-engine/authentication/authentication-authenticationhandler.html) is registered to a specific path only

## Features

### Export Package
Validates that all exported packages match a specified regular expression pattern.

### Bundle Symbolic Name
Ensures Bundle-SymbolicName headers conform to naming conventions, with support for parameter handling (e.g., `singleton:=true`).

### DS Component Provided Services
Validates that Declarative Services components only provide services whose fully qualified class names match specified patterns.

#### Implicitly Allowed Services

In addition to explicitly configured patterns, the following services are always allowed by default because they are known to support multi-tenancy or are unlikely to cause namespace clashes:

- `javax.servlet.Servlet`
- `jakarta.servlet.Servlet`
- `javax.servlet.Filter`
- `jakarta.servlet.Filter`
- `org.apache.sling.api.adapter.AdapterFactory`
- `org.apache.sling.rewriter.TransformerFactory`
- `com.adobe.granite.workflow.exec.WorkflowProcess`
- `com.day.cq.workflow.exec.WorkflowProcess`
- `org.apache.sling.auth.core.spi.AuthenticationHandler`

### HTTP/Servlet Whiteboard
For DS components implementing `javax.servlet.Servlet` or `jakarta.servlet.Servlet`, validates

- `osgi.http.whiteboard.servlet.pattern` - Servlet pattern


For DS components implementing `javax.servlet.Filter` or `jakarta.servlet.Filter`, validates

- `osgi.http.whiteboard.filter.pattern` - Servlet filter pattern

### Sling Servlet/Filter
For DS components implementing `javax.servlet.Servlet` or `jakarta.servlet.Servlet`, validates:
- `sling.servlet.paths` - Servlet path patterns
- `sling.servlet.resourceTypes` - Resource type patterns  
- `sling.servlet.resourceSuperType` - Resource super type patterns

For DS components implementing `javax.servlet.Filter` or `jakarta.servlet.Filter`, validates:
- `sling.filter.pattern` - Servlet filter patterns
- `sling.filter.resourceTypes` - Resource type patterns  

### Sling Authentication Handler
For DS components implementing `org.apache.sling.auth.core.spi.AuthenticationHandler` validates property `path`.

## Configuration

The configuration differs slightly depending on which Maven plugin is being used.
In general [Bnd's -plugin instruction](https://bnd.bndtools.org/instructions/plugin.html) is being used.

### Configuration Parameters

Parameter | Type | Description 
----------|------|-------------
`allowedExportPackagePatterns` | Pattern[] | Regular expression(s) for validating exported package names
`allowedBundleSymbolicNamePatterns` | Pattern[] | Regular expression(s) for validating Bundle-SymbolicName header
`allowedServiceClassPatterns` | Pattern[] | Regular expression(s) for validating provided service FQCNs of DS components
`allowedHttpWhiteboardServletPatterns` | Pattern[] | Regular expression(s) for validating HTTP Whiteboard servlet patterns (`osgi.http.whiteboard.servlet.pattern`)
`allowedHttpWhiteboardFilterPatterns` | Pattern[] | Regular expression(s) for validating HTTP Whiteboard filter patterns (`osgi.http.whiteboard.filter.pattern`)
`allowedSlingServletPathsPatterns` | Pattern[] | Regular expression(s) for validating Sling servlet paths (`sling.servlet.paths`)
`allowedSlingServletResourceTypesPatterns` | Pattern[] | Regular expression(s) for validating Sling servlet resource types (`sling.servlet.resourceTypes`)
`allowedSlingServletResourceSuperTypePatterns` | Pattern[] | Regular expression(s) for validating Sling servlet resource super types (`sling.servlet.resourceSuperType`)
`allowedSlingFilterPatterns` | Pattern[] | Regular expression(s) for validating Sling filter patterns (`sling.filter.pattern`)
`allowedSlingFilterResourceTypesPatterns` | Pattern[] | Regular expression(s) for validating Sling filter resource types (`sling.filter.resourceTypes`)
`allowedSlingAuthenticationHandlerPathPatterns` | Pattern[] | Regular expression(s) for validating Sling Authentication Handler's path property (`path`)

Each parameter may take multiple [regular expression patterns](https://docs.oracle.com/javase/8/docs/api/java/util/regex/Pattern.html) separated by comma. That makes the comma itself unusable within the regular expression pattern itself, however this shouldn't be necessary there.
All parameters are optional. If not set the according property/name/header is not validated.

## Usage

In general you add this artifact as plugin dependency to the Maven plugin. Then you can configure with the options outlined above.

### Example with bnd-maven-plugin Configuration Example (in POM)

```xml
<plugin>
    <groupId>biz.aQute.bnd</groupId>
    <artifactId>bnd-maven-plugin</artifactId>
    <version>7.1.0</version>
    <extensions>true</extensions>
    <configuration>
        <bnd><![CDATA[
            Bundle-Name: My OSGi Bundle
            Bundle-SymbolicName: com.mycompany.bundles.mybundle
            
            Export-Package: \
                com.mycompany.api.*,\
                com.mycompany.services.*
            
            -plugin.namespace: biz.netcentric.osgi.bnd.NamespaceValidatorsPlugin; \
                allowedExportPackagePattern="com\\.mycompany\\..*"; \
                allowedBundleSymbolicNamePatterns="com\\.mycompany\\.bundles\\..*"; \
                allowedServiceClassPatterns="com\\.mycompany\\..*"; \
                allowedSlingServletPathsPattern="/apps/myproject/.*"; \
                allowedSlingServletResourceTypesPatterns="/apps/myproject/.*"; \
                allowedSlingServletResourceSuperTypePattern="/apps/myproject/.*";
        ]]></bnd>
    </configuration>
    <dependencies>
        <dependency>
            <groupId>biz.netcentric.osgi.bnd</groupId>
            <artifactId>bundle-namespace-validators</artifactId>
            <version>1.0.0</version>
        </dependency>
    </dependencies>
</plugin>
```

## Requirements

- Java 8 or higher (builds with Java 21, targets Java 8)
- Maven 3.9.0 or higher
- Bnd 6.0.0 or higher (i.e. `bnd-maven-plugin` 6.0.0+ or `maven-bundle-plugin` 5.1.4+)

## License

This project is licensed under the Eclipse Public License 2.0 - see the [LICENSE](https://www.eclipse.org/legal/epl-2.0/) for details.

## Related Projects

- [AEM Content Package Namespace Validators](https://github.com/Netcentric/aem-content-package-namespace-validators) - Content package validation
- [Bnd Tools](https://bnd.bndtools.org/) - OSGi development tools
- [Apache Sling](https://sling.apache.org/) - Web framework for the JVM
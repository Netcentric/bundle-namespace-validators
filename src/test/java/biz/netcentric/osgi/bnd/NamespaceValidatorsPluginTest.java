/*-
 * #%L
 * Bundle Namespace Validators Bnd Plugin
 * %%
 * Copyright (C) 2025 Cognizant Netcentric
 * %%
 * All rights reserved. This program and the accompanying materials are made available under the terms of the
 * Eclipse Public License v2.0 which accompanies this distribution, and is available at
 * https://www.eclipse.org/legal/epl-v20.html
 * SPDX-License-Identifier: EPL-2.0
 * #L%
 */
package biz.netcentric.osgi.bnd;

import java.util.HashMap;
import java.util.Map;

import aQute.bnd.osgi.Analyzer;
import aQute.bnd.osgi.EmbeddedResource;
import aQute.bnd.osgi.Jar;
import aQute.bnd.osgi.Packages;
import aQute.service.reporter.Reporter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class NamespaceValidatorsPluginTest {

    private NamespaceValidatorsPlugin plugin;
    private Reporter reporter;
    private Analyzer analyzer;
    private Jar jar;

    @BeforeEach
    void setUp() {
        plugin = new NamespaceValidatorsPlugin();
        reporter = mock(Reporter.class);
        analyzer = mock(Analyzer.class);
        jar = new Jar("test");

        plugin.setReporter(reporter);

        when(analyzer.getJar()).thenReturn(jar);
        when(analyzer.getExports()).thenReturn(new Packages());
    }

    @Test
    void testDSComponentServiceValidation_ValidService() throws Exception {
        // Setup configuration with service pattern
        Map<String, String> config = new HashMap<>();
        config.put("allowedExportPackagePatterns", ".*");
        config.put("allowedServiceClassPatterns", "com\\.mycompany\\..*");
        plugin.setProperties(config);

        // Mock the Service-Component header in MANIFEST.MF
        when(analyzer.getProperty("Service-Component")).thenReturn("OSGI-INF/MyComponent.xml");

        // Create a DS component XML with a valid service
        String dsXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                + "<component xmlns=\"http://www.osgi.org/xmlns/scr/v1.1.0\" name=\"MyComponent\">\n"
                + "    <implementation class=\"com.mycompany.impl.MyComponentImpl\"/>\n"
                + "    <service>\n"
                + "        <provide interface=\"com.mycompany.api.MyService\"/>\n"
                + "    </service>\n"
                + "</component>";

        jar.putResource("OSGI-INF/MyComponent.xml", new EmbeddedResource(dsXml.getBytes(), 0));

        // Execute verification
        plugin.verify(analyzer);

        // Verify no errors were reported
        verify(reporter, never()).error(anyString(), any());
    }

    @Test
    void testDSComponentServiceValidation_InvalidService() throws Exception {
        // Setup configuration with service pattern
        Map<String, String> config = new HashMap<>();
        config.put("allowedExportPackagePatterns", ".*");
        config.put("allowedServiceClassPatterns", "com\\.mycompany\\..*");
        plugin.setProperties(config);

        // Mock the Service-Component header in MANIFEST.MF
        when(analyzer.getProperty("Service-Component")).thenReturn("OSGI-INF/MyComponent.xml");

        // Create a DS component XML with an invalid service
        String dsXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                + "<component xmlns=\"http://www.osgi.org/xmlns/scr/v1.1.0\" name=\"MyComponent\">\n"
                + "    <implementation class=\"com.mycompany.impl.MyComponentImpl\"/>\n"
                + "    <service>\n"
                + "        <provide interface=\"org.apache.sling.api.SlingService\"/>\n"
                + "    </service>\n"
                + "</component>";

        jar.putResource("OSGI-INF/MyComponent.xml", new EmbeddedResource(dsXml.getBytes(), 0));

        // Execute verification
        plugin.verify(analyzer);

        // Verify error was reported
        verify(reporter)
                .error(
                        eq(
                                "DS component \"%s\" provides service \"%s\" which does not match any of the allowed patterns [%s]"),
                        eq("MyComponent"),
                        eq("org.apache.sling.api.SlingService"),
                        startsWith("com\\.mycompany\\..*"));
    }

    @Test
    void testDSComponentServiceValidation_NoServiceComponentHeader() throws Exception {
        // Setup configuration with service pattern
        Map<String, String> config = new HashMap<>();
        config.put("allowedExportPackagePatterns", ".*");
        config.put("allowedServiceClassPatterns", "com\\.mycompany\\..*");
        plugin.setProperties(config);

        // Mock no Service-Component header in MANIFEST.MF
        when(analyzer.getProperty("Service-Component")).thenReturn(null);

        // Create a DS component XML file that won't be processed
        String dsXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                + "<component xmlns=\"http://www.osgi.org/xmlns/scr/v1.1.0\" name=\"MyComponent\">\n"
                + "    <implementation class=\"com.example.MyComponentImpl\"/>\n"
                + "    <service>\n"
                + "        <provide interface=\"org.apache.sling.api.SlingService\"/>\n"
                + "    </service>\n"
                + "</component>";

        jar.putResource("OSGI-INF/MyComponent.xml", new EmbeddedResource(dsXml.getBytes(), 0));

        // Execute verification
        plugin.verify(analyzer);

        // Verify no service validation errors were reported (since no Service-Component header)
        verify(reporter, never()).error(contains("provides service"));
    }

    @Test
    void testDSComponentServiceValidation_MultipleComponents() throws Exception {
        // Setup configuration with service pattern
        Map<String, String> config = new HashMap<>();
        config.put("allowedExportPackagePatterns", ".*");
        config.put("allowedServiceClassPatterns", "com\\.mycompany\\..*");
        plugin.setProperties(config);

        // Mock the Service-Component header with multiple components
        when(analyzer.getProperty("Service-Component"))
                .thenReturn("OSGI-INF/ValidComponent.xml, OSGI-INF/InvalidComponent.xml");

        // Create valid DS component XML
        String validDsXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                + "<component xmlns=\"http://www.osgi.org/xmlns/scr/v1.1.0\" name=\"ValidComponent\">\n"
                + "    <implementation class=\"com.mycompany.impl.ValidComponentImpl\"/>\n"
                + "    <service>\n"
                + "        <provide interface=\"com.mycompany.api.ValidService\"/>\n"
                + "    </service>\n"
                + "</component>";

        // Create invalid DS component XML
        String invalidDsXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                + "<component xmlns=\"http://www.osgi.org/xmlns/scr/v1.1.0\" name=\"InvalidComponent\">\n"
                + "    <implementation class=\"com.mycompany.impl.InvalidComponentImpl\"/>\n"
                + "    <service>\n"
                + "        <provide interface=\"org.apache.sling.api.SlingService\"/>\n"
                + "    </service>\n"
                + "</component>";

        jar.putResource("OSGI-INF/ValidComponent.xml", new EmbeddedResource(validDsXml.getBytes(), 0));
        jar.putResource("OSGI-INF/InvalidComponent.xml", new EmbeddedResource(invalidDsXml.getBytes(), 0));

        // Execute verification
        plugin.verify(analyzer);

        // Verify only the invalid component reported an error
        verify(reporter)
                .error(
                        eq(
                                "DS component \"%s\" provides service \"%s\" which does not match any of the allowed patterns [%s]"),
                        eq("InvalidComponent"),
                        eq("org.apache.sling.api.SlingService"),
                        startsWith("com\\.mycompany\\..*"));
        verify(reporter, times(1)).error(anyString(), any(), any(), any());
    }

    @Test
    void testDSComponentServiceValidation_ComponentNotFound() throws Exception {
        // Setup configuration with service pattern
        Map<String, String> config = new HashMap<>();
        config.put("allowedExportPackagePatterns", ".*");
        config.put("allowedServiceClassPatterns", "com\\.mycompany\\..*");
        plugin.setProperties(config);

        // Mock the Service-Component header referencing a non-existent file
        when(analyzer.getProperty("Service-Component")).thenReturn("OSGI-INF/NonExistentComponent.xml");

        // Execute verification
        plugin.verify(analyzer);

        // Verify warning was reported for missing file
        verify(reporter)
                .warning(
                        eq(
                                "DS component XML file \"%s\" referenced in Service-Component header but not found in bundle"),
                        eq("OSGI-INF/NonExistentComponent.xml"));
    }

    @Test
    void testDSComponentServiceValidation_WildcardPattern_StarWildcard() throws Exception {
        // Setup configuration with service pattern
        Map<String, String> config = new HashMap<>();
        config.put("allowedExportPackagePattern", ".*");
        config.put("allowedServiceClassPatterns", "com\\.mycompany\\..*");
        plugin.setProperties(config);

        // Mock the Service-Component header with wildcard pattern
        when(analyzer.getProperty("Service-Component")).thenReturn("OSGI-INF/*.xml");

        // Create multiple DS component XML files
        String validDsXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                + "<component xmlns=\"http://www.osgi.org/xmlns/scr/v1.1.0\" name=\"ValidComponent\">\n"
                + "    <implementation class=\"com.mycompany.impl.ValidComponentImpl\"/>\n"
                + "    <service>\n"
                + "        <provide interface=\"com.mycompany.api.ValidService\"/>\n"
                + "    </service>\n"
                + "</component>";

        String invalidDsXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                + "<component xmlns=\"http://www.osgi.org/xmlns/scr/v1.1.0\" name=\"InvalidComponent\">\n"
                + "    <implementation class=\"com.mycompany.impl.InvalidComponentImpl\"/>\n"
                + "    <service>\n"
                + "        <provide interface=\"org.apache.sling.api.SlingService\"/>\n"
                + "    </service>\n"
                + "</component>";

        jar.putResource("OSGI-INF/ValidComponent.xml", new EmbeddedResource(validDsXml.getBytes(), 0));
        jar.putResource("OSGI-INF/InvalidComponent.xml", new EmbeddedResource(invalidDsXml.getBytes(), 0));
        jar.putResource("OSGI-INF/NotAComponent.txt", new EmbeddedResource("not xml".getBytes(), 0));

        // Execute verification
        plugin.verify(analyzer);

        // Verify only the invalid component reported an error
        verify(reporter)
                .error(
                        eq(
                                "DS component \"%s\" provides service \"%s\" which does not match any of the allowed patterns [%s]"),
                        eq("InvalidComponent"),
                        eq("org.apache.sling.api.SlingService"),
                        startsWith("com\\.mycompany\\..*"));
        verify(reporter, times(1)).error(anyString(), any(), any(), any());
    }

    @Test
    void testDSComponentServiceValidation_WildcardPattern_QuestionMark() throws Exception {
        // Setup configuration with service pattern
        Map<String, String> config = new HashMap<>();
        config.put("allowedExportPackagePatterns", ".*");
        config.put("allowedServiceClassPatterns", "com\\.mycompany\\..*");
        plugin.setProperties(config);

        // Mock the Service-Component header with question mark wildcard
        when(analyzer.getProperty("Service-Component")).thenReturn("OSGI-INF/Component?.xml");

        // Create DS component XML files that match and don't match the pattern
        String component1Xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                + "<component xmlns=\"http://www.osgi.org/xmlns/scr/v1.1.0\" name=\"Component1\">\n"
                + "    <implementation class=\"com.mycompany.impl.Component1Impl\"/>\n"
                + "    <service>\n"
                + "        <provide interface=\"com.mycompany.api.Service1\"/>\n"
                + "    </service>\n"
                + "</component>";

        String component2Xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                + "<component xmlns=\"http://www.osgi.org/xmlns/scr/v1.1.0\" name=\"Component2\">\n"
                + "    <implementation class=\"com.mycompany.impl.Component2Impl\"/>\n"
                + "    <service>\n"
                + "        <provide interface=\"com.mycompany.api.Service2\"/>\n"
                + "    </service>\n"
                + "</component>";

        jar.putResource("OSGI-INF/Component1.xml", new EmbeddedResource(component1Xml.getBytes(), 0));
        jar.putResource("OSGI-INF/Component2.xml", new EmbeddedResource(component2Xml.getBytes(), 0));
        jar.putResource("OSGI-INF/ComponentAB.xml", new EmbeddedResource(component1Xml.getBytes(), 0)); // Won't match ?

        // Execute verification
        plugin.verify(analyzer);

        // Verify no errors were reported (all matched components have valid services)
        verify(reporter, never()).error(anyString(), any(), any(), any());
    }

    @Test
    void testDSComponentServiceValidation_WildcardPattern_SubdirectoryPattern() throws Exception {
        // Setup configuration with service pattern
        Map<String, String> config = new HashMap<>();
        config.put("allowedExportPackagePatterns", ".*");
        config.put("allowedServiceClassPatterns", "com\\.mycompany\\..*");
        plugin.setProperties(config);

        // Mock the Service-Component header with subdirectory wildcard
        when(analyzer.getProperty("Service-Component")).thenReturn("OSGI-INF/components/*.xml");

        // Create DS component XML files in subdirectory
        String validDsXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                + "<component xmlns=\"http://www.osgi.org/xmlns/scr/v1.1.0\" name=\"SubdirComponent\">\n"
                + "    <implementation class=\"com.mycompany.impl.SubdirComponentImpl\"/>\n"
                + "    <service>\n"
                + "        <provide interface=\"com.mycompany.api.SubdirService\"/>\n"
                + "    </service>\n"
                + "</component>";

        jar.putResource("OSGI-INF/components/SubdirComponent.xml", new EmbeddedResource(validDsXml.getBytes(), 0));
        jar.putResource("OSGI-INF/OtherComponent.xml", new EmbeddedResource(validDsXml.getBytes(), 0)); // Won't match

        // Execute verification
        plugin.verify(analyzer);

        // Verify no errors were reported (matched component has valid service)
        verify(reporter, never()).error(anyString(), any(), any(), any());
    }

    @Test
    void testDSComponentServiceValidation_WildcardPattern_NoMatches() throws Exception {
        // Setup configuration with service pattern
        Map<String, String> config = new HashMap<>();
        config.put("allowedExportPackagePatterns", ".*");
        config.put("allowedServiceClassPatterns", "com\\.mycompany\\..*");
        plugin.setProperties(config);

        // Mock the Service-Component header with pattern that matches nothing
        when(analyzer.getProperty("Service-Component")).thenReturn("OSGI-INF/nonexistent/*.xml");

        // Create some files that don't match
        jar.putResource("OSGI-INF/Component.xml", new EmbeddedResource("content".getBytes(), 0));

        // Execute verification
        plugin.verify(analyzer);

        // This shouldn't be reported as warning, but just as info as fully compliant with spec
        verify(reporter)
                .trace(
                        eq(
                                "DS component pattern \"%s\" referenced in Service-Component header but no matching files found in bundle"),
                        eq("OSGI-INF/nonexistent/*.xml"));
    }

    @Test
    void testDSComponentServiceValidation_MixedExactAndWildcard() throws Exception {
        // Setup configuration with service pattern
        Map<String, String> config = new HashMap<>();
        config.put("allowedExportPackagePatterns", ".*");
        config.put("allowedServiceClassPatterns", "com\\.mycompany\\..*");
        plugin.setProperties(config);

        // Mock the Service-Component header with both exact paths and wildcards
        when(analyzer.getProperty("Service-Component"))
                .thenReturn("OSGI-INF/ExactComponent.xml, OSGI-INF/wildcard/*.xml");

        // Create components for both exact and wildcard matches
        String exactComponentXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                + "<component xmlns=\"http://www.osgi.org/xmlns/scr/v1.1.0\" name=\"ExactComponent\">\n"
                + "    <implementation class=\"com.mycompany.impl.ExactComponentImpl\"/>\n"
                + "    <service>\n"
                + "        <provide interface=\"com.mycompany.api.ExactService\"/>\n"
                + "    </service>\n"
                + "</component>";

        String wildcardComponentXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                + "<component xmlns=\"http://www.osgi.org/xmlns/scr/v1.1.0\" name=\"WildcardComponent\">\n"
                + "    <implementation class=\"com.mycompany.impl.WildcardComponentImpl\"/>\n"
                + "    <service>\n"
                + "        <provide interface=\"org.apache.sling.api.InvalidService\"/>\n"
                + "    </service>\n"
                + "</component>";

        jar.putResource("OSGI-INF/ExactComponent.xml", new EmbeddedResource(exactComponentXml.getBytes(), 0));
        jar.putResource(
                "OSGI-INF/wildcard/WildcardComponent.xml", new EmbeddedResource(wildcardComponentXml.getBytes(), 0));

        // Execute verification
        plugin.verify(analyzer);

        // Verify only the wildcard component with invalid service reported an error
        verify(reporter)
                .error(
                        eq(
                                "DS component \"%s\" provides service \"%s\" which does not match any of the allowed patterns [%s]"),
                        eq("WildcardComponent"),
                        eq("org.apache.sling.api.InvalidService"),
                        startsWith("com\\.mycompany\\..*"));
        verify(reporter, times(1)).error(anyString(), any(), any(), any());
    }

    @Test
    void testBundleSymbolicNameValidation_ValidName() throws Exception {
        // Setup configuration with bundle symbolic name pattern
        Map<String, String> config = new HashMap<>();
        config.put("allowedExportPackagePatterns", ".*");
        config.put("allowedBundleSymbolicNamePatterns", "com\\.mycompany\\..*");
        plugin.setProperties(config);

        // Mock the Bundle-SymbolicName header
        when(analyzer.getProperty("Bundle-SymbolicName")).thenReturn("com.mycompany.mybundle");

        // Execute verification
        plugin.verify(analyzer);

        // Verify no errors were reported
        verify(reporter, never()).error(anyString(), any());
    }

    @Test
    void testBundleSymbolicNameValidation_InvalidName() throws Exception {
        // Setup configuration with bundle symbolic name pattern
        Map<String, String> config = new HashMap<>();
        config.put("allowedExportPackagePatterns", ".*");
        config.put("allowedBundleSymbolicNamePatterns", "com\\.mycompany\\..*");
        plugin.setProperties(config);

        // Mock the Bundle-SymbolicName header with invalid name
        when(analyzer.getProperty("Bundle-SymbolicName")).thenReturn("org.apache.invalid.bundle");

        // Execute verification
        plugin.verify(analyzer);

        // Verify error was reported
        verify(reporter)
                .error(
                        eq("Bundle-SymbolicName \"%s\" does not match any of the allowed patterns [%s]"),
                        eq("org.apache.invalid.bundle"),
                        startsWith("com\\.mycompany\\..*"));
    }

    @Test
    void testBundleSymbolicNameValidation_WithParameters() throws Exception {
        // Setup configuration with bundle symbolic name pattern
        Map<String, String> config = new HashMap<>();
        config.put("allowedExportPackagePatterns", ".*");
        config.put("allowedBundleSymbolicNamePatterns", "com\\.mycompany\\..*");
        plugin.setProperties(config);

        // Mock the Bundle-SymbolicName header with parameters (should only validate the name part)
        when(analyzer.getProperty("Bundle-SymbolicName"))
                .thenReturn("com.mycompany.mybundle;singleton:=true;version=\"1.0.0\"");

        // Execute verification
        plugin.verify(analyzer);

        // Verify no errors were reported (parameters should be ignored)
        verify(reporter, never()).error(anyString(), any());
    }

    @Test
    void testBundleSymbolicNameValidation_MissingHeader() throws Exception {
        // Setup configuration with bundle symbolic name pattern
        Map<String, String> config = new HashMap<>();
        config.put("allowedExportPackagePatterns", ".*");
        config.put("allowedBundleSymbolicNamePatterns", "com\\.mycompany\\..*");
        plugin.setProperties(config);

        // Mock missing Bundle-SymbolicName header
        when(analyzer.getProperty("Bundle-SymbolicName")).thenReturn(null);

        // Execute verification
        plugin.verify(analyzer);

        // Verify warning was reported for missing header
        verify(reporter).warning("Bundle-SymbolicName header is missing or empty");
        verify(reporter, never()).error(anyString(), any());
    }

    @Test
    void testBundleSymbolicNameValidation_EmptyHeader() throws Exception {
        // Setup configuration with bundle symbolic name pattern
        Map<String, String> config = new HashMap<>();
        config.put("allowedExportPackagePatterns", ".*");
        config.put("allowedBundleSymbolicNamePatterns", "com\\.mycompany\\..*");
        plugin.setProperties(config);

        // Mock empty Bundle-SymbolicName header
        when(analyzer.getProperty("Bundle-SymbolicName")).thenReturn("   ");

        // Execute verification
        plugin.verify(analyzer);

        // Verify warning was reported for empty header
        verify(reporter).warning("Bundle-SymbolicName header is missing or empty");
        verify(reporter, never()).error(anyString(), any());
    }

    @Test
    void testBundleSymbolicNameValidation_NoPatternConfigured() throws Exception {
        // Setup configuration without bundle symbolic name pattern
        Map<String, String> config = new HashMap<>();
        config.put("allowedExportPackagePatterns", ".*");
        plugin.setProperties(config);

        // Mock any Bundle-SymbolicName header
        when(analyzer.getProperty("Bundle-SymbolicName")).thenReturn("any.bundle.name");

        // Execute verification
        plugin.verify(analyzer);

        // Verify no validation was performed (no pattern configured)
        verify(reporter, never()).error(contains("Bundle-SymbolicName"));
        verify(reporter, never()).warning(contains("Bundle-SymbolicName"));
    }

    @Test
    void testDSComponentHttpWhiteboardContextPath_Valid() throws Exception {
        Map<String, String> config = new HashMap<>();
        config.put("allowedExportPackagePatterns", ".*");
        config.put("allowedServiceClassPatterns", "com./mycompany/..*");
        config.put("allowedHttpWhiteboardContextPathPatterns", "/valid|/another");
        plugin.setProperties(config);

        when(analyzer.getProperty("Service-Component")).thenReturn("OSGI-INF/WhiteboardComponent.xml");

        String dsXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                + "<component xmlns=\"http://www.osgi.org/xmlns/scr/v1.1.0\" name=\"WhiteboardComponent\">\n"
                + "    <implementation class=\"com.example.WhiteboardComponentImpl\"/>\n"
                + "    <service>\n"
                + "        <provide interface=\"javax.servlet.Servlet\"/>\n"
                + "    </service>\n"
                + "    <property name=\"osgi.http.whiteboard.context.path\" value=\"/valid\"/>\n"
                + "</component>";
        jar.putResource("OSGI-INF/WhiteboardComponent.xml", new EmbeddedResource(dsXml.getBytes(), 0));

        plugin.verify(analyzer);
        verify(reporter, never()).error(anyString(), any(), any(), any());
    }

    @Test
    void testDSComponentHttpWhiteboardContextPath_Invalid() throws Exception {
        Map<String, String> config = new HashMap<>();
        config.put("allowedExportPackagePatterns", ".*");
        config.put("allowedHttpWhiteboardServletPatternPatterns", "/valid|/another");
        plugin.setProperties(config);

        when(analyzer.getProperty("Service-Component")).thenReturn("OSGI-INF/WhiteboardComponent.xml");

        String dsXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                + "<component xmlns=\"http://www.osgi.org/xmlns/scr/v1.1.0\" name=\"WhiteboardComponent\">\n"
                + "    <implementation class=\"com.example.WhiteboardComponentImpl\"/>\n"
                + "    <service>\n"
                + "        <provide interface=\"javax.servlet.Servlet\"/>\n"
                + "    </service>\n"
                + "    <property name=\"osgi.http.whiteboard.servlet.pattern\" value=\"/notallowed\"/>\n"
                + "</component>";
        jar.putResource("OSGI-INF/WhiteboardComponent.xml", new EmbeddedResource(dsXml.getBytes(), 0));

        plugin.verify(analyzer);
        verify(reporter)
                .error(
                        eq(
                                "Servlet component \"%s\" has OSGi HTTP/Servlet whiteboard servlet pattern \"%s\" which does not match any of the allowed patterns [%s]"),
                        eq("WhiteboardComponent"),
                        eq("/notallowed"),
                        eq("/valid|/another"));
    }

    @Test
    void testDSComponentHttpWhiteboardContextPath_NoPatternConfigured() throws Exception {
        Map<String, String> config = new HashMap<>();
        config.put("allowedExportPackagePatterns", ".*");
        plugin.setProperties(config);

        when(analyzer.getProperty("Service-Component")).thenReturn("OSGI-INF/WhiteboardComponent.xml");

        String dsXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                + "<component xmlns=\"http://www.osgi.org/xmlns/scr/v1.1.0\" name=\"WhiteboardComponent\">\n"
                + "    <implementation class=\"com.example.WhiteboardComponentImpl\"/>\n"
                + "    <service>\n"
                + "        <provide interface=\"javax.servlet.Servlet\"/>\n"
                + "    </service>\n"
                + "    <property name=\"osgi.http.whiteboard.context.path\" value=\"/any\"/>\n"
                + "</component>";
        jar.putResource("OSGI-INF/WhiteboardComponent.xml", new EmbeddedResource(dsXml.getBytes(), 0));

        plugin.verify(analyzer);
        verify(reporter, never()).error(anyString(), any(), any(), any());
    }

    @Test
    void testAuthenticationHandlerPath_Valid() throws Exception {
        Map<String, String> config = new HashMap<>();
        config.put("allowedExportPackagePatterns", ".*");
        config.put("allowedAuthenticationHandlerPathPatterns", "/auth|/secure");
        plugin.setProperties(config);

        when(analyzer.getProperty("Service-Component")).thenReturn("OSGI-INF/AuthHandler.xml");

        String dsXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                + "<component xmlns=\"http://www.osgi.org/xmlns/scr/v1.1.0\" name=\"AuthHandler\">\n"
                + "    <implementation class=\"com.example.AuthHandlerImpl\"/>\n"
                + "    <service>\n"
                + "        <provide interface=\"org.apache.sling.auth.core.spi.AuthenticationHandler\"/>\n"
                + "    </service>\n"
                + "    <property name=\"path\" value=\"/auth\"/>\n"
                + "</component>";
        jar.putResource("OSGI-INF/AuthHandler.xml", new EmbeddedResource(dsXml.getBytes(), 0));

        plugin.verify(analyzer);
        verify(reporter, never()).error(anyString(), any(), any(), any());
    }

    @Test
    void testAuthenticationHandlerPath_Invalid() throws Exception {
        Map<String, String> config = new HashMap<>();
        config.put("allowedExportPackagePatterns", ".*");
        config.put("allowedAuthenticationHandlerPathPatterns", "/auth|/secure");
        plugin.setProperties(config);

        when(analyzer.getProperty("Service-Component")).thenReturn("OSGI-INF/AuthHandler.xml");

        String dsXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                + "<component xmlns=\"http://www.osgi.org/xmlns/scr/v1.1.0\" name=\"AuthHandler\">\n"
                + "    <implementation class=\"com.example.AuthHandlerImpl\"/>\n"
                + "    <service>\n"
                + "        <provide interface=\"org.apache.sling.auth.core.spi.AuthenticationHandler\"/>\n"
                + "    </service>\n"
                + "    <property name=\"path\" value=\"/notallowed\"/>\n"
                + "</component>";
        jar.putResource("OSGI-INF/AuthHandler.xml", new EmbeddedResource(dsXml.getBytes(), 0));

        plugin.verify(analyzer);
        verify(reporter)
                .error(
                        eq(
                                "AuthenticationHandler component \"%s\" has path \"%s\" which does not match any of the allowed patterns [%s]"),
                        eq("AuthHandler"),
                        eq("/notallowed"),
                        eq("/auth|/secure"));
    }

    @Test
    void testAuthenticationHandlerPath_NoPatternConfigured() throws Exception {
        Map<String, String> config = new HashMap<>();
        config.put("allowedExportPackagePatterns", ".*");
        plugin.setProperties(config);

        when(analyzer.getProperty("Service-Component")).thenReturn("OSGI-INF/AuthHandler.xml");

        String dsXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                + "<component xmlns=\"http://www.osgi.org/xmlns/scr/v1.1.0\" name=\"AuthHandler\">\n"
                + "    <implementation class=\"com.example.AuthHandlerImpl\"/>\n"
                + "    <service>\n"
                + "        <provide interface=\"org.apache.sling.auth.core.spi.AuthenticationHandler\"/>\n"
                + "    </service>\n"
                + "    <property name=\"path\" value=\"/any\"/>\n"
                + "</component>";
        jar.putResource("OSGI-INF/AuthHandler.xml", new EmbeddedResource(dsXml.getBytes(), 0));

        plugin.verify(analyzer);
        verify(reporter, never()).error(anyString(), any(), any(), any());
    }

    @Test
    void testAuthenticationHandlerPath_MultiplePaths() throws Exception {
        Map<String, String> config = new HashMap<>();
        config.put("allowedExportPackagePatterns", ".*");
        config.put("allowedAuthenticationHandlerPathPatterns", "/auth|/secure");
        plugin.setProperties(config);

        when(analyzer.getProperty("Service-Component")).thenReturn("OSGI-INF/AuthHandler.xml");

        String dsXml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                + "<component xmlns=\"http://www.osgi.org/xmlns/scr/v1.1.0\" name=\"AuthHandler\">\n"
                + "    <implementation class=\"com.example.AuthHandlerImpl\"/>\n"
                + "    <service>\n"
                + "        <provide interface=\"org.apache.sling.auth.core.spi.AuthenticationHandler\"/>\n"
                + "    </service>\n"
                + "    <property name=\"path\" value=\"/auth,/notallowed\"/>\n"
                + "</component>";
        jar.putResource("OSGI-INF/AuthHandler.xml", new EmbeddedResource(dsXml.getBytes(), 0));

        plugin.verify(analyzer);
        verify(reporter)
                .error(
                        eq(
                                "AuthenticationHandler component \"%s\" has path \"%s\" which does not match any of the allowed patterns [%s]"),
                        eq("AuthHandler"),
                        eq("/notallowed"),
                        eq("/auth|/secure"));
    }
}

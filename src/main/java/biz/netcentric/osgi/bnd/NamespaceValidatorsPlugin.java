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

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.StringTokenizer;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import aQute.bnd.annotation.plugin.BndPlugin;
import aQute.bnd.osgi.Analyzer;
import aQute.bnd.osgi.Constants;
import aQute.bnd.osgi.Descriptors.PackageRef;
import aQute.bnd.osgi.Jar;
import aQute.bnd.osgi.Resource;
import aQute.bnd.service.Plugin;
import aQute.bnd.service.verifier.VerifierPlugin;
import aQute.lib.converter.Converter;
import aQute.service.reporter.Reporter;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

@BndPlugin(name = "NamespaceValidatorsPlugin", parameters = NamespaceValidatorsPlugin.Config.class)
public class NamespaceValidatorsPlugin implements VerifierPlugin, Plugin {

    private Config config;
    private Reporter reporter;
    private final DocumentBuilderFactory documentBuilderFactory;

    // OSGi/Bnd constants
    private static final String OSGI_INF = "OSGI-INF";

    // XML parsing constants
    private static final String XML_FEATURE_DISALLOW_DOCTYPE = "http://apache.org/xml/features/disallow-doctype-decl";
    private static final String XML_FEATURE_EXTERNAL_GENERAL_ENTITIES =
            "http://xml.org/sax/features/external-general-entities";
    private static final String XML_FEATURE_EXTERNAL_PARAMETER_ENTITIES =
            "http://xml.org/sax/features/external-parameter-entities";
    private static final String XML_FEATURE_LOAD_EXTERNAL_DTD =
            "http://apache.org/xml/features/nonvalidating/load-external-dtd";

    // DS component XML constants
    private static final String DS_COMPONENT_ELEMENT = "component";
    private static final String DS_SERVICE_ELEMENT = "service";
    private static final String DS_PROVIDE_ELEMENT = "provide";
    private static final String DS_NAME_ATTRIBUTE = "name";
    private static final String DS_INTERFACE_ATTRIBUTE = "interface";
    private static final String DS_PROPERTY_ELEMENT = "property";
    private static final String DS_PROPERTY_NAME_ATTRIBUTE = "name";
    private static final String DS_PROPERTY_VALUE_ATTRIBUTE = "value";

    private static final Collection<String> SERVLET_INTERFACES =
            Arrays.asList("javax.servlet.Servlet", "jakarta.servlet.Servlet");

    private static final Collection<String> FILTER_INTERFACES =
            Arrays.asList("javax.servlet.Filter", "jakarta.servlet.Filter");
    // Sling servlet/filter constants
    private static final String SLING_SERVLET_PATHS = "sling.servlet.paths";
    private static final String SLING_SERVLET_RESOURCE_TYPES = "sling.servlet.resourceTypes";
    private static final String SLING_SERVLET_RESOURCE_SUPER_TYPE = "sling.servlet.resourceSuperType";
    private static final String SLING_FILTER_PATTERN = "sling.filter.pattern";
    private static final Object SLING_FILTER_RESOURCE_TYPES = "sling.filter.resourceTypes";

    // HTTP Whiteboard and Jakarta Servlet constants
    private static final String HTTP_WHITEBOARD_SERVLET_PATTERN = "osgi.http.whiteboard.servlet.pattern";
    private static final String HTTP_WHITEBOARD_FILTER_PATTERN = "osgi.http.whiteboard.filter.pattern";

    // AuthenticationHandler constants
    private static final String AUTHENTICATION_HANDLER_INTERFACE =
            "org.apache.sling.auth.core.spi.AuthenticationHandler";
    private static final String AUTH_HANDLER_PATH_PROPERTY = "path";

    private static final Collection<String> KNOWN_KEYS = Arrays.asList(
            "allowedExportPackagePatterns",
            "allowedServiceClassPatterns",
            "allowedBundleSymbolicNamePatterns",
            "allowedHttpWhiteboardServletPatternPatterns",
            "allowedHttpWhiteboardFilterPatternPatterns",
            "allowedSlingServletPathsPatterns",
            "allowedSlingServletResourceTypesPatterns",
            "allowedSlingServletResourceSuperTypePatterns",
            "allowedSlingFilterPatternPatterns",
            "allowedSlingFilterResourceTypesPatterns",
            "allowedSlingAuthenticationHandlerPathPatterns");

    private static final Collection<Pattern> ALLOWED_TENANT_SPECIFIC_SERVICES;

    static {
        // list those service interfaces which fully support multi-tenancy or are known to almost never clash
        ALLOWED_TENANT_SPECIFIC_SERVICES = new LinkedList<>();
        SERVLET_INTERFACES.forEach(
                iface -> ALLOWED_TENANT_SPECIFIC_SERVICES.add(Pattern.compile(Pattern.quote(iface))));
        FILTER_INTERFACES.forEach(iface -> ALLOWED_TENANT_SPECIFIC_SERVICES.add(Pattern.compile(Pattern.quote(iface))));
        ALLOWED_TENANT_SPECIFIC_SERVICES.add(
                Pattern.compile(Pattern.quote("org.apache.sling.api.adapter.AdapterFactory")));
        ALLOWED_TENANT_SPECIFIC_SERVICES.add(
                Pattern.compile(Pattern.quote("org.apache.sling.rewriter.TransformerFactory")));
        ALLOWED_TENANT_SPECIFIC_SERVICES.add(
                Pattern.compile(Pattern.quote("com.adobe.granite.workflow.exec.WorkflowProcess")));
        ALLOWED_TENANT_SPECIFIC_SERVICES.add(
                Pattern.compile(Pattern.quote("com.day.cq.workflow.exec.WorkflowProcess")));
        ALLOWED_TENANT_SPECIFIC_SERVICES.add(Pattern.compile(Pattern.quote(AUTHENTICATION_HANDLER_INTERFACE)));
    }

    public NamespaceValidatorsPlugin() {
        // Initialize secure DocumentBuilderFactory to prevent XXE attacks
        this.documentBuilderFactory = DocumentBuilderFactory.newInstance();
        this.documentBuilderFactory.setNamespaceAware(true);

        // Security settings to prevent XXE attacks
        try {
            this.documentBuilderFactory.setFeature(XML_FEATURE_DISALLOW_DOCTYPE, true);
            this.documentBuilderFactory.setFeature(XML_FEATURE_EXTERNAL_GENERAL_ENTITIES, false);
            this.documentBuilderFactory.setFeature(XML_FEATURE_EXTERNAL_PARAMETER_ENTITIES, false);
            this.documentBuilderFactory.setFeature(XML_FEATURE_LOAD_EXTERNAL_DTD, false);
            this.documentBuilderFactory.setXIncludeAware(false);
            this.documentBuilderFactory.setExpandEntityReferences(false);
        } catch (ParserConfigurationException e) {
            throw new IllegalStateException("Failed to configure XML parser for secure processing", e);
        }
    }

    /**
     * Effective allowed service class patterns including both explicitly allowed patterns as well as default services whose multi-tenancy is validated via properties.
     */
    private Collection<Pattern> effectiveAllowedServiceClassPatterns;

    interface Config {
        Collection<Pattern> allowedExportPackagePatterns();

        /**
         * Pattern for validating OSGi service FQCNs implemented by DS components.
         * If not specified, no service validation is performed.
         * This is merged with a set of default patterns allowing servlet and filter interfaces which come with multi-tenancy support through some properties validated separately.
         */
        Collection<Pattern> allowedServiceClassPatterns();

        /**
         * Pattern for validating Bundle-SymbolicName header.
         * If not specified, no bundle symbolic name validation is performed.
         */
        Collection<Pattern> allowedBundleSymbolicNamePatterns();

        /**
         * Patterns for validating HTTP Whiteboard filter pattern property (osgi.http.whiteboard.filter.pattern).
         * If not specified, no HTTP Whiteboard filter pattern validation is performed.
         */
        Collection<Pattern> allowedHttpWhiteboardFilterPatternPatterns();

        /**
         * Patterns for validating HTTP Whiteboard servlet pattern property (osgi.http.whiteboard.servlet.pattern).
         * If not specified, no HTTP Whiteboard servlet pattern validation is performed.
         */
        Collection<Pattern> allowedHttpWhiteboardServletPatternPatterns();

        /**
         * Pattern for validating Sling servlet paths property (sling.servlet.paths).
         * If not specified, no servlet paths validation is performed.
         */
        Collection<Pattern> allowedSlingServletPathsPatterns();

        /**
         * Patterns for validating Sling servlet resource types property (sling.servlet.resourceTypes).
         * If not specified, no servlet resource types validation is performed.
         */
        Collection<Pattern> allowedSlingServletResourceTypesPatterns();

        /**
         * Patterns for validating Sling servlet resource super type property (sling.servlet.resourceSuperType).
         * If not specified, no servlet resource super type validation is performed.
         */
        Collection<Pattern> allowedSlingServletResourceSuperTypePatterns();

        /**
         * Patterns for validating Slings AuthenticationHandler path property (path).
         * If not specified, no AuthenticationHandler path validation is performed.
         */
        Collection<Pattern> allowedSlingAuthenticationHandlerPathPatterns();

        /**
         * Patterns for validating Sling filter pattern property (sling.filter.pattern).
         * If not specified, no Sling filter pattern validation is performed.
         */
        Collection<Pattern> allowedSlingFilterPatternPatterns();

        /**
         * Patterns for validating Sling filter resource types property (sling.filter.resourceTypes).
         * If not specified, no servlet resource types validation is performed.
         */
        Collection<Pattern> allowedSlingFilterResourceTypesPatterns();
    }

    @Override
    public void setProperties(Map<String, String> map) throws Exception {
        // split comma-separated values into collections
        Map<String, Collection<String>> multiValueMap = map.entrySet().stream()
                .collect(Collectors.toMap(
                        Entry::getKey, entry -> Arrays.asList(entry.getValue().split(","))));
        this.config = Converter.cnv(Config.class, multiValueMap);

        // Emit warning for unknown keys
        for (String key : map.keySet()) {
            if (!KNOWN_KEYS.contains(key)) {
                if (reporter != null) {
                    reporter.warning("Unknown configuration key for NamespaceValidatorsPlugin: '%s'", key);
                }
            }
        }

        if (this.config.allowedServiceClassPatterns() != null) {
            this.effectiveAllowedServiceClassPatterns = new LinkedList<>(this.config.allowedServiceClassPatterns());
            // TODO: conditionally add depending on the multi-tenancy property is being validated
            // what is the condition?
            this.effectiveAllowedServiceClassPatterns.addAll(ALLOWED_TENANT_SPECIFIC_SERVICES);
        }
    }

    @Override
    public void setReporter(Reporter reporter) {
        this.reporter = reporter;
    }

    @Override
    public void verify(Analyzer analyzer) throws Exception {
        checkPackages(analyzer.getExports().keySet());
        checkBundleSymbolicName(analyzer.getProperty(Constants.BUNDLE_SYMBOLICNAME));
        checkDSComponentServices(analyzer);
    }

    private void checkPackages(Collection<PackageRef> packages) {
        if (config.allowedExportPackagePatterns() == null
                || config.allowedExportPackagePatterns().isEmpty()) {
            return; // No export package patterns configured, skip validation
        }
        for (PackageRef pkg : packages) {
            if (config.allowedExportPackagePatterns().stream()
                    .noneMatch(pattern -> pattern.matcher(pkg.getFQN()).matches())) {
                reporter.error(
                        "Exported package \"%s\" does not match any of the allowed patterns [%s]",
                        pkg.getFQN(),
                        config.allowedExportPackagePatterns().stream()
                                .map(Pattern::pattern)
                                .collect(Collectors.joining(",")));
            }
        }
    }

    /**
     * Checks if the Bundle-SymbolicName header matches the configured pattern.
     */
    private void checkBundleSymbolicName(String bundleSymbolicName) {
        if (config.allowedBundleSymbolicNamePatterns() == null
                || config.allowedBundleSymbolicNamePatterns().isEmpty()) {
            return; // No bundle symbolic name pattern configured, skip validation
        }

        if (bundleSymbolicName == null || bundleSymbolicName.trim().isEmpty()) {
            reporter.warning("Bundle-SymbolicName header is missing or empty");
            return;
        }

        // The Bundle-SymbolicName may contain parameters (e.g., ";singleton:=true")
        // We only want to validate the symbolic name part, not the parameters
        String symbolicNameOnly = bundleSymbolicName.split(";")[0].trim();

        if (config.allowedBundleSymbolicNamePatterns().stream()
                .noneMatch(pattern -> pattern.matcher(symbolicNameOnly).matches())) {
            reporter.error(
                    "Bundle-SymbolicName \"%s\" does not match any of the allowed patterns [%s]",
                    symbolicNameOnly,
                    config.allowedBundleSymbolicNamePatterns().stream()
                            .map(Pattern::pattern)
                            .collect(Collectors.joining(",")));
        }
    }

    /**
     * Checks if OSGi DS components implement services whose FQCN matches the configured pattern
     * and validates Sling servlet properties and HTTP Whiteboard properties.
     */
    private void checkDSComponentServices(Analyzer analyzer) {
        boolean shouldCheck = (effectiveAllowedServiceClassPatterns != null)
                || (config.allowedSlingServletPathsPatterns() != null
                        && !config.allowedSlingServletPathsPatterns().isEmpty())
                || (config.allowedSlingServletResourceTypesPatterns() != null
                        && !config.allowedSlingServletResourceTypesPatterns().isEmpty())
                || (config.allowedSlingServletResourceSuperTypePatterns() != null
                        && !config.allowedSlingServletResourceSuperTypePatterns()
                                .isEmpty())
                || (config.allowedHttpWhiteboardServletPatternPatterns() != null
                        && !config.allowedHttpWhiteboardServletPatternPatterns().isEmpty())
                || (config.allowedSlingAuthenticationHandlerPathPatterns() != null
                        && !config.allowedSlingAuthenticationHandlerPathPatterns()
                                .isEmpty());
        if (!shouldCheck) {
            return; // No relevant patterns configured, skip validation
        }

        Jar jar = analyzer.getJar();
        if (jar == null) {
            return;
        }

        // Get the Service-Component header from MANIFEST.MF
        String serviceComponentHeader = analyzer.getProperty(Constants.SERVICE_COMPONENT);
        if (serviceComponentHeader == null || serviceComponentHeader.trim().isEmpty()) {
            return; // No DS components declared in manifest
        }

        // Parse the Service-Component header to get the list of XML files or patterns
        String[] componentPaths = serviceComponentHeader.split(",");
        Map<String, Resource> resources = jar.getResources();

        for (String componentPath : componentPaths) {
            String trimmedPath = componentPath.trim();
            if (trimmedPath.isEmpty()) {
                continue;
            }

            // Handle paths that might not start with OSGI-INF/
            if (!trimmedPath.startsWith(OSGI_INF + "/")) {
                trimmedPath = OSGI_INF + "/" + trimmedPath;
            }

            // Check if path contains wildcards
            if (trimmedPath.contains("*")) {
                // Handle wildcard patterns
                processWildcardPattern(trimmedPath, resources);
            } else {
                // Handle exact path
                processExactPath(trimmedPath, resources);
            }
        }
    }

    /**
     * Processes a wildcard pattern to find matching DS component XML files.
     */
    private void processWildcardPattern(String pattern, Map<String, Resource> resources) {
        // Convert glob pattern to regex
        String regex = globToRegex(pattern);
        Pattern compiledPattern = Pattern.compile(regex);

        boolean foundAny = false;
        for (Map.Entry<String, Resource> entry : resources.entrySet()) {
            String resourcePath = entry.getKey();
            if (compiledPattern.matcher(resourcePath).matches()) {
                foundAny = true;
                Resource resource = entry.getValue();
                try (InputStream is = resource.openInputStream()) {
                    validateDSComponentXML(resourcePath, is);
                } catch (Exception e) {
                    reporter.warning("Failed to parse DS component XML file \"%s\": %s", resourcePath, e.getMessage());
                }
            }
        }

        if (!foundAny) {
            reporter.trace(
                    "DS component pattern \"%s\" referenced in Service-Component header but no matching files found in bundle",
                    pattern);
        }
    }

    /**
     * Processes an exact path to find a specific DS component XML file.
     */
    private void processExactPath(String path, Map<String, Resource> resources) {
        Resource resource = resources.get(path);
        if (resource != null) {
            try (InputStream is = resource.openInputStream()) {
                validateDSComponentXML(path, is);
            } catch (Exception e) {
                reporter.warning("Failed to parse DS component XML file \"%s\": %s", path, e.getMessage());
            }
        } else {
            reporter.warning(
                    "DS component XML file \"%s\" referenced in Service-Component header but not found in bundle",
                    path);
        }
    }

    /**
     * Converts a glob pattern to a regular expression.
     */
    private String globToRegex(String glob) {
        StringBuilder regex = new StringBuilder();
        boolean inCharClass = false;

        for (int i = 0; i < glob.length(); i++) {
            char c = glob.charAt(i);
            switch (c) {
                case '*':
                    if (inCharClass) {
                        regex.append(c);
                    } else {
                        regex.append(".*");
                    }
                    break;
                case '?':
                    if (inCharClass) {
                        regex.append(c);
                    } else {
                        regex.append(".");
                    }
                    break;
                case '[':
                    inCharClass = true;
                    regex.append(c);
                    break;
                case ']':
                    inCharClass = false;
                    regex.append(c);
                    break;
                case '\\':
                case '^':
                case '$':
                case '.':
                case '{':
                case '}':
                case '(':
                case ')':
                case '+':
                case '|':
                    regex.append('\\').append(c);
                    break;
                default:
                    regex.append(c);
                    break;
            }
        }

        return regex.toString();
    }

    /**
     * Validates a single DS component XML file for service interface compliance and Sling servlet properties.
     */
    private void validateDSComponentXML(String path, InputStream xmlStream)
            throws ParserConfigurationException, SAXException, IOException {
        DocumentBuilder builder = documentBuilderFactory.newDocumentBuilder();
        Document doc = builder.parse(xmlStream);

        Element root = doc.getDocumentElement();
        if (!DS_COMPONENT_ELEMENT.equals(root.getLocalName())) {
            return; // Not a DS component XML
        }

        // Get the component name for error reporting
        String componentName = root.getAttribute(DS_NAME_ATTRIBUTE);
        if (componentName == null || componentName.isEmpty()) {
            componentName = path;
        }

        // Check if this component implements Servlet interface
        boolean isServletComponent =
                SERVLET_INTERFACES.stream().anyMatch(iface -> isComponentImplementingInterface(root, iface));
        boolean isFilterComponent =
                FILTER_INTERFACES.stream().anyMatch(iface -> isComponentImplementingInterface(root, iface));
        boolean isAuthenticationHandlerComponent =
                isComponentImplementingInterface(root, AUTHENTICATION_HANDLER_INTERFACE);

        Map<String, Collection<String>> properties = getComponentProperties(root);

        // Validate service interfaces if pattern is configured
        if (config.allowedServiceClassPatterns() != null
                && !config.allowedServiceClassPatterns().isEmpty()) {
            validateServiceProviders(componentName, root);
        }

        // Validate Sling servlet properties if this is a servlet component and patterns are configured
        if (isServletComponent) {
            validateServletProperties(componentName, properties);
        }

        // Validate filter patterns if this is a filter component
        if (isFilterComponent) {
            validateFilterPatterns(componentName, properties);
        }

        // Validate AuthenticationHandler path if this is an AuthenticationHandler component
        if (isAuthenticationHandlerComponent) {
            validateAuthenticationHandlerPath(componentName, properties);
        }
    }

    /**
     * Checks if the DS component implements the given interface.
     */
    private boolean isComponentImplementingInterface(Element componentElement, String interfaceName) {
        NodeList serviceElements = componentElement.getElementsByTagName(DS_SERVICE_ELEMENT);
        for (int i = 0; i < serviceElements.getLength(); i++) {
            Element serviceElement = (Element) serviceElements.item(i);
            NodeList provideElements = serviceElement.getElementsByTagName(DS_PROVIDE_ELEMENT);
            for (int j = 0; j < provideElements.getLength(); j++) {
                Element provideElement = (Element) provideElements.item(j);
                String providedInterface = provideElement.getAttribute(DS_INTERFACE_ATTRIBUTE);
                if (interfaceName.equals(providedInterface)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Validates service provider classes against the configured patterns.
     */
    private void validateServiceProviders(String componentName, Element componentElement) {
        NodeList serviceElements = componentElement.getElementsByTagName(DS_SERVICE_ELEMENT);
        for (int i = 0; i < serviceElements.getLength(); i++) {
            Element serviceElement = (Element) serviceElements.item(i);

            NodeList provideElements = serviceElement.getElementsByTagName(DS_PROVIDE_ELEMENT);
            for (int j = 0; j < provideElements.getLength(); j++) {
                Element provideElement = (Element) provideElements.item(j);
                String interfaceName = provideElement.getAttribute(DS_INTERFACE_ATTRIBUTE);

                if (interfaceName != null && !interfaceName.isEmpty()) {
                    if (effectiveAllowedServiceClassPatterns.stream()
                            .noneMatch(pattern -> pattern.matcher(interfaceName).matches())) {
                        reporter.error(
                                "DS component \"%s\" provides service \"%s\" which does not match any of the allowed patterns [%s]",
                                componentName,
                                interfaceName,
                                effectiveAllowedServiceClassPatterns.stream()
                                        .map(Pattern::pattern)
                                        .collect(Collectors.joining(",")));
                    }
                }
            }
        }
    }

    /**
     * Retrieves all properties of a DS component as a map of property name to collection of values.
     * Handles properties with a 'value' attribute (comma-separated values) and supports multi-valued properties.
     */
    private Map<String, Collection<String>> getComponentProperties(Element componentElement) {
        Map<String, Collection<String>> properties = new java.util.HashMap<>();
        NodeList propertyElements = componentElement.getElementsByTagName(DS_PROPERTY_ELEMENT);
        for (int i = 0; i < propertyElements.getLength(); i++) {
            Element propertyElement = (Element) propertyElements.item(i);
            String propertyName = propertyElement.getAttribute(DS_PROPERTY_NAME_ATTRIBUTE);
            Objects.requireNonNull(propertyName, "Property name in DS component cannot be null");
            String propertyValue = null;
            if (propertyElement.hasAttribute(DS_PROPERTY_VALUE_ATTRIBUTE)) {
                propertyValue = propertyElement.getAttribute(DS_PROPERTY_VALUE_ATTRIBUTE);
            }
            List<String> valueList = new ArrayList<>();
            if (propertyValue != null) {
                valueList.add(propertyValue);
            } else {
                // If no 'value' attribute, check for text content (could be multi-line)
                StringTokenizer tokener = new StringTokenizer(propertyElement.getTextContent(), "\r\n");
                while (tokener.hasMoreTokens()) {
                    String value = tokener.nextToken().trim();
                    if (!value.isEmpty()) {
                        valueList.add(value);
                    }
                }
            }
            properties.put(propertyName, valueList);
        }
        return properties;
    }

    /**
     * Validates servlet properties against configured patterns considering both Sling servlets and OSGi HTTP (Servlet) Whiteboard servlets.
     */
    private void validateServletProperties(String componentName, Map<String, Collection<String>> properties) {
        // Validate sling.servlet.paths
        if (properties.containsKey(SLING_SERVLET_PATHS)
                && config.allowedSlingServletPathsPatterns() != null
                && !config.allowedSlingServletPathsPatterns().isEmpty()) {
            for (String path : properties.get(SLING_SERVLET_PATHS)) {
                String trimmedPath = path.trim();
                if (config.allowedSlingServletPathsPatterns().stream()
                        .noneMatch(pattern -> pattern.matcher(trimmedPath).matches())) {
                    reporter.error(
                            "Sling servlet component \"%s\" has servlet path \"%s\" which does not match any of the allowed patterns [%s]",
                            componentName,
                            trimmedPath,
                            config.allowedSlingServletPathsPatterns().stream()
                                    .map(Pattern::pattern)
                                    .collect(Collectors.joining(",")));
                }
            }
        }
        // Validate sling.servlet.resourceTypes
        if (properties.containsKey(SLING_SERVLET_RESOURCE_TYPES)
                && config.allowedSlingServletResourceTypesPatterns() != null) {
            for (String resourceType : properties.get(SLING_SERVLET_RESOURCE_TYPES)) {
                String trimmedResourceType = resourceType.trim();
                if (config.allowedSlingServletResourceTypesPatterns().stream()
                        .noneMatch(
                                pattern -> pattern.matcher(trimmedResourceType).matches())) {
                    reporter.error(
                            "Sling servlet component \"%s\" has resource type \"%s\" which does not match any of the allowed patterns [%s]",
                            componentName,
                            trimmedResourceType,
                            config.allowedSlingServletResourceTypesPatterns().stream()
                                    .map(Pattern::pattern)
                                    .collect(Collectors.joining(",")));
                }
            }
        }
        // Validate sling.servlet.resourceSuperType
        if (properties.containsKey(SLING_SERVLET_RESOURCE_SUPER_TYPE)
                && config.allowedSlingServletResourceSuperTypePatterns() != null) {
            for (String propertyValue : properties.get(SLING_SERVLET_RESOURCE_SUPER_TYPE)) {
                if (config.allowedSlingServletResourceSuperTypePatterns().stream()
                        .noneMatch(pattern -> pattern.matcher(propertyValue).matches())) {
                    reporter.error(
                            "Sling servlet component \"%s\" has resource super type \"%s\" which does not match any of the allowed patterns [%s]",
                            componentName,
                            propertyValue,
                            config.allowedSlingServletResourceSuperTypePatterns().stream()
                                    .map(Pattern::pattern)
                                    .collect(Collectors.joining(",")));
                }
            }
        }
        // Validate osgi.http.whiteboard.servlet.pattern
        if (properties.containsKey(HTTP_WHITEBOARD_SERVLET_PATTERN)
                && config.allowedHttpWhiteboardServletPatternPatterns() != null
                && !config.allowedHttpWhiteboardServletPatternPatterns().isEmpty()) {
            for (String propertyValue : properties.get(HTTP_WHITEBOARD_SERVLET_PATTERN)) {
                if (config.allowedHttpWhiteboardServletPatternPatterns().stream()
                        .noneMatch(pattern -> pattern.matcher(propertyValue).matches())) {
                    reporter.error(
                            "Servlet component \"%s\" has OSGi HTTP/Servlet whiteboard servlet pattern \"%s\" which does not match any of the allowed patterns [%s]",
                            componentName,
                            propertyValue,
                            config.allowedHttpWhiteboardServletPatternPatterns().stream()
                                    .map(Pattern::pattern)
                                    .collect(Collectors.joining(",")));
                }
            }
        }
    }

    /**
     * Validates AuthenticationHandler path against configured patterns.
     */
    private void validateAuthenticationHandlerPath(String componentName, Map<String, Collection<String>> properties) {
        if (config.allowedSlingAuthenticationHandlerPathPatterns() == null
                || config.allowedSlingAuthenticationHandlerPathPatterns().isEmpty()) {
            return;
        }
        if (properties.containsKey(AUTH_HANDLER_PATH_PROPERTY)) {
            for (String path : properties.get(AUTH_HANDLER_PATH_PROPERTY)) {
                String trimmedPath = path.trim();
                if (config.allowedSlingAuthenticationHandlerPathPatterns().stream()
                        .noneMatch(pattern -> pattern.matcher(trimmedPath).matches())) {
                    reporter.error(
                            "AuthenticationHandler component \"%s\" has path \"%s\" which does not match any of the allowed patterns [%s]",
                            componentName,
                            trimmedPath,
                            config.allowedSlingAuthenticationHandlerPathPatterns().stream()
                                    .map(Pattern::pattern)
                                    .collect(Collectors.joining(",")));
                }
            }
        }
    }

    /**
     * Validates filter patterns for Sling and OSGi HTTP/Servlet Whiteboard filters.
     */
    private void validateFilterPatterns(String componentName, Map<String, Collection<String>> properties) {
        // Validate sling.filter.pattern
        if (properties.containsKey(SLING_FILTER_PATTERN)
                && config.allowedSlingFilterPatternPatterns() != null
                && !config.allowedSlingFilterPatternPatterns().isEmpty()) {
            for (String pattern : properties.get(SLING_FILTER_PATTERN)) {
                String trimmedPattern = pattern.trim();
                if (config.allowedSlingFilterPatternPatterns().stream()
                        .noneMatch(p -> p.matcher(trimmedPattern).matches())) {
                    reporter.error(
                            "Sling filter component \"%s\" has filter pattern \"%s\" which does not match any of the patterns [%s]",
                            componentName,
                            trimmedPattern,
                            config.allowedSlingFilterPatternPatterns().stream()
                                    .map(Pattern::pattern)
                                    .collect(Collectors.joining(",")));
                }
            }
        }
        // Validate sling.filter.resourceTypes
        if (properties.containsKey(SLING_FILTER_RESOURCE_TYPES)
                && config.allowedSlingFilterResourceTypesPatterns() != null
                && !config.allowedSlingFilterResourceTypesPatterns().isEmpty()) {
            for (String pattern : properties.get(SLING_FILTER_RESOURCE_TYPES)) {
                String trimmedPattern = pattern.trim();
                if (config.allowedSlingFilterResourceTypesPatterns().stream()
                        .noneMatch(p -> p.matcher(trimmedPattern).matches())) {
                    reporter.error(
                            "Sling filter component \"%s\" has resource type \"%s\" which does not match any of the patterns [%s]",
                            componentName,
                            trimmedPattern,
                            config.allowedSlingFilterResourceTypesPatterns().stream()
                                    .map(Pattern::pattern)
                                    .collect(Collectors.joining(",")));
                }
            }
        }
        // Validate osgi.http.whiteboard.filter.pattern
        if (properties.containsKey(HTTP_WHITEBOARD_FILTER_PATTERN)
                && config.allowedHttpWhiteboardFilterPatternPatterns() != null
                && !config.allowedHttpWhiteboardFilterPatternPatterns().isEmpty()) {
            for (String pattern : properties.get(HTTP_WHITEBOARD_FILTER_PATTERN)) {
                String trimmedPattern = pattern.trim();
                if (config.allowedHttpWhiteboardFilterPatternPatterns().stream()
                        .noneMatch(p -> p.matcher(trimmedPattern).matches())) {
                    reporter.error(
                            "HTTP Whiteboard filter component \"%s\" has filter pattern \"%s\" which does not match any of the patterns [%s]",
                            componentName,
                            trimmedPattern,
                            config.allowedHttpWhiteboardFilterPatternPatterns().stream()
                                    .map(Pattern::pattern)
                                    .collect(Collectors.joining(",")));
                }
            }
        }
    }
}

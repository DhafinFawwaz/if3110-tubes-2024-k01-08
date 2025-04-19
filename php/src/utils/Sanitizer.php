<?php

namespace src\utils;

class Sanitizer {
    private static $allowedTags = [
        'a', 'p', 'span', 'div', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'ul', 'ol', 'li', 'b', 
        'i', 'u', 'em', 'strong', 'strike', 'sub', 'sup', 'hr', 'br', 'blockquote', 'caption', 
        'code', 'pre', 'col', 'colgroup', 'table', 'tbody', 'td', 'tfoot', 'th', 'thead', 'tr'
    ];

    private static $allowedAttributes = [
        'a' => ['href', 'name', 'target', 'rel'],
        'span' => ['style'],
        'p' => ['class'],
        'li' => ['class'],
        'pre' => ['class']
    ];

    private static $allowedStyles = [
        'background-color' => '/^rgb\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*\)$/',
        'color' => '/^rgb\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})\s*\)$/'
    ];

    private static $allowedClasses = [
        'ql-align-right', 'ql-align-center', 'ql-align-justify', 'ql-code-block', 
        'ql-code-block-container', 'ql-syntax', 'ql-direction-rtl', 'ql-font-serif', 
        'ql-font-monospace', 'ql-formula', 'ql-indent-1', 'ql-indent-2', 'ql-indent-3', 
        'ql-indent-4', 'ql-indent-5', 'ql-indent-6', 'ql-indent-7', 'ql-indent-8', 
        'ql-size-small', 'ql-size-large', 'ql-size-huge'
    ];

    public static function sanitize(string $html): string {
        if (empty(trim($html))) {
            return '';
        }

        $dom = new \DOMDocument();
        libxml_use_internal_errors(true);

        $dom->loadHTML('<?xml encoding="utf-8" ?>' . $html, LIBXML_HTML_NOIMPLIED | LIBXML_HTML_NODEFDTD);
        libxml_clear_errors();

        if ($dom->documentElement) {
            self::sanitizeNode($dom->documentElement);
            return $dom->saveHTML();
        }

        return '';
    }

    private static function sanitizeNode(\DOMNode $node) {
        if ($node instanceof \DOMElement) {
            if (!in_array($node->tagName, self::$allowedTags)) {
                $node->parentNode->removeChild($node);
                return;
            }

            foreach (iterator_to_array($node->attributes) as $attr) {
                if (!self::isAllowedAttribute($node->tagName, $attr)) {
                    $node->removeAttribute($attr->name);
                }
            }

            if ($node->hasAttribute('style')) {
                self::sanitizeStyles($node);
            }

            if ($node->hasAttribute('class')) {
                self::sanitizeClasses($node);
            }
        }

        foreach (iterator_to_array($node->childNodes) as $childNode) {
            self::sanitizeNode($childNode);
        }
    }

    private static function isAllowedAttribute(string $tag, \DOMAttr $attr): bool {
        return isset(self::$allowedAttributes[$tag]) && in_array($attr->name, self::$allowedAttributes[$tag]);
    }

    private static function sanitizeStyles(\DOMElement $element) {
        $style = $element->getAttribute('style');
        $newStyle = [];

        foreach (explode(';', $style) as $rule) {
            if (strpos($rule, ':') !== false) {
                [$property, $value] = array_map('trim', explode(':', $rule, 2));
                if (isset(self::$allowedStyles[$property]) && preg_match(self::$allowedStyles[$property], $value)) {
                    $newStyle[] = "$property: $value";
                }
            }
        }

        $element->setAttribute('style', implode('; ', $newStyle));
    }

    private static function sanitizeClasses(\DOMElement $element) {
        $classes = explode(' ', $element->getAttribute('class'));
        $newClasses = array_filter($classes, function ($class) {
            return in_array($class, self::$allowedClasses);
        });

        $element->setAttribute('class', implode(' ', $newClasses));
    }
}
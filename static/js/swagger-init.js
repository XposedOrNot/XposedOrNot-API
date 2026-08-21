window.onload = function () {
    const ui = SwaggerUIBundle({
        url: "/openapi.json",
        dom_id: '#swagger-ui',
        deepLinking: true,
        docExpansion: "list",
        defaultModelsExpandDepth: 1,
        displayOperationId: true,
        filter: true,
        showExtensions: true,
        showCommonExtensions: true,
        displayRequestDuration: true,
        persistAuthorization: true,
        tryItOutEnabled: true,
        maxDisplayedTags: null,
        syntaxHighlight: {
            theme: "monokai",
            activated: true,
        },
        layout: "BaseLayout",
        presets: [
            SwaggerUIBundle.presets.apis,
            SwaggerUIBundle.SwaggerUIStandalonePreset
        ],
        plugins: [
            SwaggerUIBundle.plugins.DownloadUrl
        ],
        requestInterceptor: (req) => {
            return req;
        },
        modelPropertyMacro: null,
        responseInterceptor: (res) => {
            return res;
        },
        onComplete: function () {
            const descriptionElement = document.querySelector('.swagger-ui .info .description');
            if (descriptionElement) {
                descriptionElement.innerHTML = descriptionElement.innerHTML
                    .replace(/`([^`]+)`/g, '<code>$1</code>')
                    .split('\n\n')
                    .map(p => `<p>${p}</p>`)
                    .join('');
            }
        },
        // Filter out analytics and default routes
        tagsSorter: (tagA, tagB) => {
            if (tagA === 'analytics' || tagA === 'default') return 1;
            if (tagB === 'analytics' || tagB === 'default') return -1;
            return tagA.localeCompare(tagB);
        },
        // Filter function to exclude analytics and default routes
        filterSpecSelector: (spec) => {
            const paths = spec.paths;
            const filteredPaths = {};

            for (const path in paths) {
                const operations = paths[path];
                let include = true;

                for (const method in operations) {
                    const operation = operations[method];
                    if (operation.tags && (operation.tags.includes('analytics') || operation.tags.includes('default'))) {
                        include = false;
                        break;
                    }
                }

                if (include) {
                    filteredPaths[path] = paths[path];
                }
            }

            spec.paths = filteredPaths;
            return spec;
        }
    });
    window.ui = ui;
}

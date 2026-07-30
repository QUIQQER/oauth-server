(function () {
    'use strict';

    const Script = document.currentScript;

    if (!Script) {
        return;
    }

    const settings = Script.dataset;
    const container = document.getElementById('quiqqer-oauth-login-control');

    if (!container || !settings.returnUri) {
        return;
    }

    window.URL_DIR = settings.urlDir;
    window.URL_BIN_DIR = settings.urlBinDir;
    window.URL_OPT_DIR = settings.urlOptDir;
    window.URL_SYS_DIR = settings.urlSysDir;
    window.QUIQQER_FRONTEND = 1;
    window.QUIQQER_CONFIG = {
        globals: {
            no_ajax_bundler: 1
        }
    };

    require.config({
        baseUrl: settings.urlBinDir + 'QUI/',
        paths: {
            package: settings.urlOptDir,
            qui: settings.urlOptDir + 'bin/qui/qui',
            locale: settings.urlVarDir + 'locale/bin',
            Ajax: settings.urlBinDir + 'QUI/Ajax',
            URL_OPT_DIR: settings.urlOptDir,
            URL_BIN_DIR: settings.urlBinDir,
            Mustache: settings.urlOptDir
                + 'bin/quiqqer-asset/mustache/mustache/mustache.min',
            URI: settings.urlOptDir
                + 'bin/quiqqer-asset/urijs/urijs/src/URI',
            IPv6: settings.urlOptDir
                + 'bin/quiqqer-asset/urijs/urijs/src/IPv6',
            punycode: settings.urlOptDir
                + 'bin/quiqqer-asset/urijs/urijs/src/punycode',
            SecondLevelDomains: settings.urlOptDir
                + 'bin/quiqqer-asset/urijs/urijs/src/SecondLevelDomains'
        },
        waitSeconds: 0,
        catchError: true,
        map: {
            '*': {
                css: settings.urlOptDir + 'bin/qui/qui/lib/css.js'
            }
        }
    });

    require([
        'qui/QUI',
        'Locale',
        'controls/users/Login',
        'locale/quiqqer/core/' + settings.language
    ], function (QUI, Locale, Login) {
        Locale.setCurrent(settings.language);
        QUI.setAttributes({
            'control-loader-type': 'line-scale',
            'control-loader-color': '#2f8fc8'
        });

        new Login({
            onSuccess: function () {
                window.location.replace(settings.returnUri);
            }
        }).inject(container);
    });
}());

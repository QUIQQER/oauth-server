/**
 * Manage restrictions of OAuth2 scopes
 *
 * @module package/quiqqer/oauth-server/bin/backend/controls/ScopeSettings
 * @author Patrick Müller <https://www.pcsg.de>
 *
 * @event onLoaded [this] - fires if the controls has finished loading
 */
define('package/quiqqer/oauth-server/bin/backend/controls/ScopeSettings', [

    'qui/controls/Control',
    'qui/controls/loader/Loader',

    'package/quiqqer/oauth-server/bin/backend/OAuthServer',

    'Locale',
    'Mustache',

    'text!package/quiqqer/oauth-server/bin/backend/controls/ScopeSettings.html',
    'text!package/quiqqer/oauth-server/bin/backend/controls/ScopeSettings.Row.html',
    'css!package/quiqqer/oauth-server/bin/backend/controls/ScopeSettings.css'

], function (QUIControl, QUILoader, OAuthServer, QUILocale, Mustache, template, templateRow) {
    "use strict";

    var lg = 'quiqqer/oauth-server';

    return new Class({

        Extends: QUIControl,
        Type   : 'package/quiqqer/oauth-server/bin/backend/controls/ScopeSettings',

        Binds: [
            '$onInject',
            '$onImport',
            'getSettings'
        ],

        options: {
            settings: {}
        },

        initialize: function (options) {
            this.parent(options);

            this.$Input    = null;
            this.$Content  = null;
            this.$Settings = options.settings || {};
            this.Loader    = new QUILoader();

            this.addEvents({
                onInject: this.$onInject
            });
        },

        /**
         * event: onInject
         */
        $onInject: function () {
            this.$Content = this.getElm();
            this.Loader.inject(this.$Content);

            this.$build();
        },

        /**
         * Build scopes settings table
         *
         * @return {Promise}
         */
        $build: function () {
            var self     = this;
            var lgPrefix = 'controls.backend.ScopeSettings.template.';

            this.$Content.set('html', Mustache.render(template, {
                headerScope : QUILocale.get(lg, lgPrefix + 'headerScope'),
                headerActive: QUILocale.get(lg, lgPrefix + 'headerActive'),
                headerCalls : QUILocale.get(lg, lgPrefix + 'headerCalls')
            }));

            this.Loader.show();

            var switchUnlimited = function (event) {
                var Row = event.target.getParent(
                    '.quiqqer-oauth-server-scopesettings-scope'
                );

                Row.getElement('input[name="maxCalls"]').disabled      = event.target.checked;
                Row.getElement('select[name="maxCallsType"]').disabled = event.target.checked;
            };

            return OAuthServer.getScopes().then(function (scopes) {
                var TableBody = self.$Content.getElement('tbody');

                var labelUnlimitedCalls        = QUILocale.get(lg, lgPrefix + 'labelUnlimitedCalls'),
                    labelMaxCalls              = QUILocale.get(lg, lgPrefix + 'labelMaxCalls'),
                    labelMaxCallsType          = QUILocale.get(lg, lgPrefix + 'labelMaxCallsType'),
                    maxCallsTypeOptionAbsolute = QUILocale.get(lg, lgPrefix + 'maxCallsTypeOptionAbsolute'),
                    maxCallsTypeOptionMinute   = QUILocale.get(lg, lgPrefix + 'maxCallsTypeOptionMinute'),
                    maxCallsTypeOptionHour     = QUILocale.get(lg, lgPrefix + 'maxCallsTypeOptionHour'),
                    maxCallsTypeOptionDay      = QUILocale.get(lg, lgPrefix + 'maxCallsTypeOptionDay'),
                    maxCallsTypeOptionMonth    = QUILocale.get(lg, lgPrefix + 'maxCallsTypeOptionMonth'),
                    maxCallsTypeOptionYear     = QUILocale.get(lg, lgPrefix + 'maxCallsTypeOptionYear');

                for (var i = 0, len = scopes.length; i < len; i++) {
                    var scope = scopes[i];

                    var Row = new Element('tr', {
                        'class'     : 'quiqqer-oauth-server-scopesettings-scope',
                        'data-scope': scope,
                        html        : Mustache.render(templateRow, {
                            scope                     : scope,
                            labelUnlimitedCalls       : labelUnlimitedCalls,
                            labelMaxCalls             : labelMaxCalls,
                            labelMaxCallsType         : labelMaxCallsType,
                            maxCallsTypeOptionAbsolute: maxCallsTypeOptionAbsolute,
                            maxCallsTypeOptionMinute  : maxCallsTypeOptionMinute,
                            maxCallsTypeOptionHour    : maxCallsTypeOptionHour,
                            maxCallsTypeOptionDay     : maxCallsTypeOptionDay,
                            maxCallsTypeOptionMonth   : maxCallsTypeOptionMonth,
                            maxCallsTypeOptionYear    : maxCallsTypeOptionYear
                        })
                    }).inject(TableBody);

                    var UnlimitedCheckbox = Row.getElement('input[name="unlimitedCalls"]');

                    UnlimitedCheckbox.addEvent('change', switchUnlimited);

                    if (!(scope in self.$Settings)) {
                        self.$Settings[scope] = {
                            active        : false,
                            maxCalls      : 0,
                            maxCallsType  : 'absolute',
                            unlimitedCalls: true
                        };
                    }

                    var settings = self.$Settings[scope];

                    Row.getElement('input[name="active"]').checked = settings.active;
                    UnlimitedCheckbox.checked                      = settings.unlimitedCalls;

                    var MaxCallsInput     = Row.getElement('input[name="maxCalls"]'),
                        MaxCallsTypeInput = Row.getElement('select[name="maxCallsType"]');

                    MaxCallsInput.value     = settings.maxCalls;
                    MaxCallsTypeInput.value = settings.maxCallsType;

                    if (!UnlimitedCheckbox.checked) {
                        MaxCallsInput.disabled     = false;
                        MaxCallsTypeInput.disabled = false;
                    }
                }

                self.Loader.hide();
                self.fireEvent('loaded', [self]);
            });
        },

        /**
         * Return all current settings
         *
         * @return {Object}
         */
        getSettings: function () {
            var rows = this.$Content.getElements('.quiqqer-oauth-server-scopesettings-scope');

            for (var i = 0, len = rows.length; i < len; i++) {
                var Row   = rows[i];
                var scope = Row.get('data-scope');

                this.$Settings[scope] = {
                    active        : Row.getElement('input[name="active"]').checked,
                    maxCalls      : Row.getElement('input[name="maxCalls"]').value,
                    maxCallsType  : Row.getElement('select[name="maxCallsType"]').value,
                    unlimitedCalls: Row.getElement('input[name="unlimitedCalls"]').checked
                };
            }

            return this.$Settings;
        }
    });
});

/**
 * Manage restrictions of OAuth2 scopes
 *
 * @module package/quiqqer/oauth-server/bin/backend/controls/ScopeSettings
 * @author Patrick Müller <https://www.pcsg.de>
 *
 * @event onLoaded [this] - fires if the controls has finished loading
 */
define('package/quiqqer/oauth-server/bin/backend/controls/ScopeSettings', [

    'qui/QUI',
    'qui/controls/Control',
    'qui/controls/loader/Loader',
    'qui/controls/windows/Confirm',
    'qui/controls/buttons/Switch',

    'package/quiqqer/oauth-server/bin/backend/OAuthServer',


    'Locale',
    'Mustache',

    'text!package/quiqqer/oauth-server/bin/backend/controls/ScopeSettings.html',
    'text!package/quiqqer/oauth-server/bin/backend/controls/ScopeSettings.Row.html',
    'text!package/quiqqer/oauth-server/bin/backend/controls/ScopeSettings.Limits.html',
    'css!package/quiqqer/oauth-server/bin/backend/controls/ScopeSettings.css'

], function (QUI, QUIControl, QUILoader, QUIConfirm, QUISwitch, OAuthServer, QUILocale, Mustache,
             template, templateRow, templateLimits) {
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
            settings: {},
            clientId: false // if provided, the usage limits (options) for this client are shown
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
                headerScope: QUILocale.get(lg, lgPrefix + 'headerScope'),
                headerCalls: QUILocale.get(lg, lgPrefix + 'headerCalls')
            }));

            this.Loader.show();

            var switchUnlimited = function (Switch) {
                var Row = Switch.getElm().getParent(
                    '.quiqqer-oauth-server-scopesettings-scope'
                );

                Row.getElement('input[name="maxCalls"]').disabled      = Switch.getStatus();
                Row.getElement('select[name="maxCallsType"]').disabled = Switch.getStatus();
            };

            var resolve = [OAuthServer.getScopes()];

            if (this.getAttribute('clientId')) {
                resolve.push(OAuthServer.getLimits(this.getAttribute('clientId')));
            }

            Promise.all(
                resolve
            ).then(function (result) {
                var scopes = result[0],
                    Limits = false;

                if (typeof result[1] !== 'undefined') {
                    Limits = result[1];
                }

                var TableBody = self.$Content.getElement('tbody');

                var labelActive                = QUILocale.get(lg, lgPrefix + 'labelActive'),
                    labelUnlimitedCalls        = QUILocale.get(lg, lgPrefix + 'labelUnlimitedCalls'),
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
                            labelActive               : labelActive,
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

                    if (!(scope in self.$Settings)) {
                        self.$Settings[scope] = {
                            active        : false,
                            maxCalls      : 0,
                            maxCallsType  : 'absolute',
                            unlimitedCalls: true
                        };
                    }

                    var settings = self.$Settings[scope];

                    // Active switch
                    new QUISwitch({
                        status: settings.active
                    }).inject(
                        Row.getElement('.quiqqer-oauth-server-scopesettings-table-active')
                    );

                    // Unlimited switch
                    var UnlimitedSwitch = new QUISwitch({
                        status: settings.unlimitedCalls,
                        events: {
                            onChange: switchUnlimited
                        }
                    }).inject(
                        Row.getElement('.quiqqer-oauth-server-scopesettings-table-unlimited')
                    );

                    var MaxCallsInput     = Row.getElement('input[name="maxCalls"]'),
                        MaxCallsTypeInput = Row.getElement('select[name="maxCallsType"]');

                    MaxCallsInput.value     = settings.maxCalls;
                    MaxCallsTypeInput.value = settings.maxCallsType;

                    if (!UnlimitedSwitch.getStatus()) {
                        MaxCallsInput.disabled     = false;
                        MaxCallsTypeInput.disabled = false;
                    }

                    if (Limits && scope in Limits) {
                        self.$getLimitsElm(scope, Limits[scope]).inject(
                            Row.getElement('td.quiqqer-oauth-server-scopesettings-table-limits')
                        );
                    }
                }

                self.Loader.hide();
                self.fireEvent('loaded', [self]);
            });
        },

        /**
         * Get element that shows the limit options for a scope
         *
         * @param {String} scope
         * @param {Object} LimitData
         * @return {HTMLElement}
         */
        $getLimitsElm: function (scope, LimitData) {
            var self     = this;
            var lgPrefix = 'controls.backend.ScopeSettings.limits.template.';

            var limitReached = '';

            if (LimitData.queryLimitReached) {
                limitReached = QUILocale.get(lg, lgPrefix + 'limitReached');
            }

            var LimitsElm = new Element('div', {
                'class': 'quiqqer-oauth-server-scopesettings-limits',
                html   : Mustache.render(templateLimits, {
                    labelTotalUsageCount   : QUILocale.get(lg, lgPrefix + 'labelTotalUsageCount'),
                    labelIntervalUsageCount: QUILocale.get(lg, lgPrefix + 'labelIntervalUsageCount'),
                    labelReset             : QUILocale.get(lg, lgPrefix + 'labelReset'),
                    labelFirstUsage        : QUILocale.get(lg, lgPrefix + 'labelFirstUsage'),
                    labelLastUsage         : QUILocale.get(lg, lgPrefix + 'labelLastUsage'),
                    totalUsageCount        : LimitData.total_usage_count,
                    intervalUsageCount     : LimitData.interval_usage_count,
                    firstUsage             : LimitData.first_usage,
                    lastUsage              : LimitData.last_usage,
                    limitReached           : limitReached
                })
            });

            var Reset = LimitsElm.getElement('.quiqqer-oauth-server-scopesettings-limits-reset');

            Reset.addEvent('click', function (event) {
                event.stop();

                new QUIConfirm({
                    maxHeight: 300,
                    autoclose: false,

                    information: QUILocale.get(lg, 'controls.backend.ScopeSettings.limits.reset.text', {
                        clientId: self.getAttribute('clientId'),
                        scope   : scope
                    }),
                    title      : QUILocale.get(lg, 'controls.backend.ScopeSettings.limits.reset.title'),
                    texticon   : 'fa fa-repeat',
                    text       : QUILocale.get(lg, 'controls.backend.ScopeSettings.limits.reset.title'),
                    icon       : 'fa fa-repeat',

                    cancel_button: {
                        text     : false,
                        textimage: 'icon-remove fa fa-remove'
                    },
                    ok_button    : {
                        text     : false,
                        textimage: 'icon-ok fa fa-check'
                    },
                    events       : {
                        onSubmit: function (Popup) {
                            Popup.Loader.show();

                            OAuthServer.resetLimits(
                                self.getAttribute('clientId'),
                                scope
                            ).then(function () {
                                Popup.close();
                                self.$build();
                            }, function () {
                                Popup.Loader.hide();
                            });
                        }
                    }

                }).open();
            });

            return LimitsElm;
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

                var ActiveSwitch = QUI.Controls.getById(
                    Row.getElement(
                        '.quiqqer-oauth-server-scopesettings-table-active > div.qui-switch'
                    ).get('data-quiid')
                );

                var UnlimitedSwitch = QUI.Controls.getById(
                    Row.getElement(
                        '.quiqqer-oauth-server-scopesettings-table-unlimited > div.qui-switch'
                    ).get('data-quiid')
                );

                this.$Settings[scope] = {
                    active        : ActiveSwitch.getStatus(),
                    maxCalls      : Row.getElement('input[name="maxCalls"]').value,
                    maxCallsType  : Row.getElement('select[name="maxCallsType"]').value,
                    unlimitedCalls: UnlimitedSwitch.getStatus()
                };
            }

            return this.$Settings;
        }
    });
});

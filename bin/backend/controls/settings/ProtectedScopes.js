/**
 * Manage restrictions of OAuth2 scopes
 *
 * @module package/quiqqer/oauth-server/bin/backend/controls/settings/ProtectedScopes
 * @author Patrick Müller <https://www.pcsg.de>
 *
 * @event onLoaded [this] - fires if the controls has finished loading
 */
define('package/quiqqer/oauth-server/bin/backend/controls/settings/ProtectedScopes', [

    'qui/controls/Control',
    'qui/controls/loader/Loader',
    'qui/controls/buttons/Switch',

    'package/quiqqer/oauth-server/bin/backend/OAuthServer',


    'Locale',
    'Mustache',

    'text!package/quiqqer/oauth-server/bin/backend/controls/settings/ProtectedScopes.html',
    'text!package/quiqqer/oauth-server/bin/backend/controls/settings/ProtectedScopes.Row.html',
    'css!package/quiqqer/oauth-server/bin/backend/controls/settings/ProtectedScopes.css'

], function (QUIControl, QUILoader, QUISwitch, OAuthServer, QUILocale, Mustache, template, templateRow) {
    "use strict";

    var lg = 'quiqqer/oauth-server';

    return new Class({

        Extends: QUIControl,
        Type   : 'package/quiqqer/oauth-server/bin/backend/controls/settings/ProtectedScopes',

        Binds: [
            '$onInject',
            '$onImport',
            'getSettings'
        ],

        initialize: function (options) {
            this.parent(options);

            this.$Input    = null;
            this.$Content  = null;
            this.$Settings = {};
            this.Loader    = new QUILoader();

            this.addEvents({
                onImport: this.$onImport
            });
        },

        /**
         * Event: onImport
         *
         */
        $onImport: function () {
            this.$Input      = this.getElm();
            this.$Input.type = 'hidden';

            if (this.$Input.value !== '') {
                this.$Settings = JSON.decode(this.$Input.value);
            }

            this.$Content = new Element('div', {
                'class': 'quiqqer-oauth-server-protectedscopes'
            }).inject(this.$Input, 'after');

            this.$build();
        },

        /**
         * Build scopes settings table
         *
         * @return {Promise}
         */
        $build: function () {
            var self     = this;
            var lgPrefix = 'controls.backend.settings.ProtectedScopes.template.';

            this.$Content.set('html', Mustache.render(template, {
                headerScope    : QUILocale.get(lg, lgPrefix + 'headerScope'),
                headerProtected: QUILocale.get(lg, lgPrefix + 'headerProtected')
            }));

            this.Loader.show();

            var switchProtected = function (Switch) {
                var Row = Switch.getElm().getParent(
                    '.quiqqer-oauth-server-protectedscopes-scope'
                );

                var scope = Row.get('data-scope');

                self.$Settings[scope] = Switch.getStatus();
                self.$Input.value     = JSON.encode(self.$Settings);
            };

            OAuthServer.getScopes().then(function (scopes) {
                var TableBody      = self.$Content.getElement('tbody');
                var labelProtected = QUILocale.get(lg, lgPrefix + 'labelProtected');

                for (var i = 0, len = scopes.length; i < len; i++) {
                    var scope = scopes[i];

                    var Row = new Element('tr', {
                        'class'     : 'quiqqer-oauth-server-protectedscopes-scope',
                        'data-scope': scope,
                        html        : Mustache.render(templateRow, {
                            scope         : scope,
                            labelProtected: labelProtected
                        })
                    }).inject(TableBody);

                    if (!(scope in self.$Settings)) {
                        self.$Settings[scope] = true;
                    }

                    // Active switch
                    new QUISwitch({
                        status: self.$Settings[scope],
                        events: {
                            onChange: switchProtected
                        }
                    }).inject(
                        Row.getElement('.quiqqer-oauth-server-protectedscopes-table-protected')
                    );
                }

                self.Loader.hide();
                self.fireEvent('loaded', [self]);
            });
        }
    });
});

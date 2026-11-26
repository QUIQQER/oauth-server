/**
 * Manage OAuth2 clients for a QUIQQER user
 *
 * @module package/quiqqer/oauth-server/bin/backend/controls/UserClients
 * @author www.pcsg.de (Patrick Müller)
 */
define('package/quiqqer/oauth-server/bin/backend/controls/UserClients', [

    'qui/controls/Control',
    'qui/controls/windows/Confirm',
    'qui/controls/windows/Popup',
    'qui/controls/buttons/Button',
    'qui/controls/loader/Loader',

    'package/quiqqer/oauth-server/bin/backend/controls/ScopeSettings',
    'package/quiqqer/oauth-server/bin/backend/OAuthServer',

    'controls/grid/Grid',
    'Locale',
    'Mustache',

    'text!package/quiqqer/oauth-server/bin/backend/controls/UserClients.Create.html',
    'text!package/quiqqer/oauth-server/bin/backend/controls/UserClients.Edit.html',
    'css!package/quiqqer/oauth-server/bin/backend/controls/UserClients.css'

], function (QUIControl, QUIConfirm, QUIPopup, QUIButton, QUILoader, ScopeSettings, OAuthServer, Grid,
    QUILocale, Mustache, templateCreate, templateEdit) {
    "use strict";

    var lg = 'quiqqer/oauth-server';

    function getAuthorizationLabels() {
        const prefix = 'control.user.clients.authorization.';

        return {
            labelClientType: QUILocale.get(lg, prefix + 'type'),
            labelRestClient: QUILocale.get(lg, prefix + 'rest'),
            labelAuthorizationClient: QUILocale.get(lg, prefix + 'pkce'),
            labelRedirectUris: QUILocale.get(lg, prefix + 'redirectUris'),
            labelResources: QUILocale.get(lg, prefix + 'resources'),
            labelOneUriPerLine: QUILocale.get(lg, prefix + 'oneUriPerLine'),
            labelDynamicConfiguration: QUILocale.get(lg, prefix + 'dynamicConfiguration')
        };
    }

    function readAuthorizationSettings(Content) {
        const readLines = (name) => Content.querySelector(`[data-name="${name}"]`)
            .value.split(/\r?\n/)
            .map((uri) => uri.trim())
            .filter((uri) => uri !== '');

        return {
            redirectUris: readLines('redirect-uris'),
            resources: readLines('resources')
        };
    }

    function showSaveError(Content, error) {
        Content.querySelector('[data-name="dialog-error"]').textContent =
            error?.getMessage?.() || error?.message || QUILocale.get(lg, 'control.user.clients.dialog.saveError');
    }

    return new Class({

        Extends: QUIControl,
        Type   : 'package/quiqqer/oauth-server/bin/backend/controls/UserClients',

        Binds: [
            'refresh',
            'createClient',
            'openDeleteDialog',
            'editClient',
            '$getUser'
        ],

        options: {
            User: false
        },

        initialize: function (options) {
            this.parent(options);

            this.$Grid  = null;
            this.Loader = new QUILoader();
            this.$User  = null;

            this.addEvents({
                onImport: this.$onImport,
                onInject: this.$onInject
            });
        },

        /**
         * Replace the XML settings placeholder with the client list container.
         */
        $onImport: function () {
            const Input = this.getElm();
            const Table = Input.closest('table');
            const Container = document.createElement('div');

            Container.setAttribute('data-quiid', this.getId());
            Container.setAttribute('data-name', 'oauth-clients');
            (Table || Input).replaceWith(Container);
            this.$Elm = Container;
            this.$onInject();
        },

        /**
         * event: on inject
         */
        $onInject: function () {
            var self = this,
                Elm  = this.getElm();

            var Container = new Element('div', {
                styles: {
                    height: '100%',
                    width : '100%'
                }
            }).inject(Elm);

            var PanelContent = Elm.getParent('.qui-panel-content');

            this.$Grid = new Grid(Container, {
                pagination : true,
                buttons    : [{
                    name     : 'add',
                    text     : QUILocale.get(lg, 'control.user.clients.button.add'),
                    textimage: 'fa fa-plus',
                    events   : {
                        onClick: function (Btn) {
                            Btn.setAttribute('textimage', 'fa fa-spinner fa-spin');
                            self.createClient().then(function () {
                                Btn.setAttribute('textimage', 'fa fa-plus');
                            });
                        }
                    }
                }, {
                    name     : 'edit',
                    text     : QUILocale.get(lg, 'control.user.clients.button.edit'),
                    textimage: 'fa fa-edit',
                    disabled : true,
                    events   : {
                        onClick: this.editClient
                    }
                }, {
                    name     : 'delete',
                    text     : '',
                    icon     : 'fa fa-trash',
                    title    : QUILocale.get(lg, 'control.user.clients.button.delete'),
                    position : 'right',
                    disabled : true,
                    events   : {
                        onClick: this.openDeleteDialog
                    }
                }],
                columnModel: [{
                    header   : QUILocale.get('quiqqer/core', 'name'),
                    dataIndex: 'name',
                    dataType : 'string',
                    width    : 200
                }, {
                    header   : QUILocale.get(lg, 'client_id'),
                    dataIndex: 'client_id',
                    dataType : 'string',
                    width    : 400
                }]
            });

            this.$Grid.setHeight(
                PanelContent.getSize().y - 40
            );

            this.$Grid.addEvents({
                onRefresh : this.refresh,
                onClick   : function () {
                    var selected     = self.$Grid.getSelectedIndices(),
                        TableButtons = self.$Grid.getAttribute('buttons');

                    if (selected.length === 1) {
                        TableButtons.edit.enable();
                        TableButtons.delete.enable();
                    } else {
                        TableButtons.edit.disable();
                        TableButtons.delete.disable();
                    }
                },
                onDblClick: this.editClient
            });

            this.Loader.inject(Elm);

            this.refresh();
        },

        /**
         * Refresh the list
         *
         * @returns {Promise}
         */
        refresh: function () {
            var self = this;

            this.Loader.show();

            return this.$getUser().then(function (User) {
                return OAuthServer.getClientList(User.getId());
            }).then(function (result) {
                self.$Grid.setData({
                    data: result
                });

                self.Loader.hide();
            });
        },

        /**
         * Get User
         *
         * @return {Promise}
         */
        $getUser: function () {
            var self = this;

            if (this.$User) {
                return Promise.resolve(this.$User);
            }

            return new Promise(function (resolve) {
                var waitForUser = setInterval(function () {
                    if (!self.getAttribute('User')) {
                        return;
                    }

                    clearInterval(waitForUser);

                    self.$User = self.getAttribute('User');
                    resolve(self.$User);
                }, 200);
            });
        },

        /**
         * Create a new client
         *
         * @returns {Promise}
         */
        createClient: function () {
            let ScopeSettingsControl;
            let ready = false;
            let saving = false;

            return new Promise((resolve) => {
                const Popup = new QUIPopup({
                    icon           : 'fa fa-plus',
                    title          : QUILocale.get(
                        lg, 'controls.backend.UserClient.createClient.popup.title'
                    ),
                    maxHeight      : 600,
                    maxWidth       : 1000,
                    closeButtonText: QUILocale.get(lg, 'controls.backend.UserClient.createClient.popup.close.text'),
                    events         : {
                        onOpen : function (Popup) {
                            const lgPrefix = 'controls.backend.UserClients.createClient.template.';
                            const Content = Popup.getContent();

                            Popup.setContent(Mustache.render(templateCreate, {
                                ...getAuthorizationLabels(),
                                labelName         : QUILocale.get(lg, lgPrefix + 'labelName'),
                                labelScopeSettings: QUILocale.get(lg, lgPrefix + 'labelScopeSettings')
                            }));

                            const ClientType = Content.querySelector('[data-name="client-type"]');
                            const AuthorizationFields = Content.querySelector('[data-name="authorization-fields"]');

                            ClientType.addEventListener('change', () => {
                                AuthorizationFields.hidden = ClientType.value !== 'authorization_code';
                                Content.querySelector('[data-name="dialog-error"]').textContent = '';
                            });

                            Popup.Loader.show();

                            ScopeSettingsControl = new ScopeSettings({
                                events: {
                                    onLoaded: function (Control) {
                                        Control.getElm().classList.add('field-container-field');
                                        ready = true;
                                        Popup.Loader.hide();
                                    }
                                }
                            }).inject(
                                Content.querySelector('[data-name="scope-settings"]')
                            );

                            Content.querySelector('[data-name="client-name"]').focus();
                        },
                        onClose: function () {
                            resolve();
                        }
                    }
                });

                Popup.open();

                Popup.addButton(new QUIButton({
                    text  : QUILocale.get(lg, 'controls.backend.UserClient.createClient.popup.confirm.text'),
                    alt   : QUILocale.get(lg, 'controls.backend.UserClient.createClient.popup.confirm'),
                    title : QUILocale.get(lg, 'controls.backend.UserClient.createClient.popup.confirm'),
                    events: {
                        onClick: async () => {
                            if (!ready || saving) {
                                return;
                            }

                            const Content = Popup.getContent();
                            const clientType = Content.querySelector('[data-name="client-type"]').value;
                            const authorization = clientType === 'authorization_code'
                                ? readAuthorizationSettings(Content)
                                : null;

                            saving = true;
                            Content.querySelector('[data-name="dialog-error"]').textContent = '';
                            Popup.Loader.show();

                            try {
                                await OAuthServer.createClient(
                                    this.getAttribute('User').getId(),
                                    ScopeSettingsControl.getSettings(),
                                    Content.querySelector('[data-name="client-name"]').value,
                                    authorization
                                );
                            } catch (error) {
                                showSaveError(Content, error);
                                saving = false;
                                Popup.Loader.hide();
                                return;
                            }

                            Popup.close();
                            this.refresh();
                        }
                    }
                }));
            });
        },

        /**
         * Dialogs
         */

        /**
         * Opens the delete dialog
         */
        openDeleteDialog: function () {
            var self = this,
                data = this.$Grid.getSelectedData()[0];

            new QUIConfirm({
                title      : QUILocale.get(lg, 'control.user.clients.window.delete.title'),
                text       : QUILocale.get(lg, 'control.user.clients.window.delete.title'),
                information: QUILocale.get(lg, 'control.user.clients.window.delete.text', {
                    name    : data.name,
                    clientId: data.client_id
                }),
                icon       : 'fa fa-trash',
                texticon   : 'fa fa-trash',
                maxWidth   : 600,
                maxHeight  : 400,
                autoclose  : false,
                events     : {
                    onSubmit: function (Win) {
                        Win.Loader.show();

                        OAuthServer.deleteClient(data.client_id).then(function () {
                            return self.refresh();
                        }).then(function () {
                            Win.close();
                            self.refresh();
                        }, function () {
                            Win.Loader.hide();
                        });
                    }
                }
            }).open();
        },

        /**
         * Opens the edit dialog
         */
        editClient: function () {
            const data = this.$Grid.getSelectedData()[0];
            let ScopeSettingsControl;
            let canEditAuthorization = false;
            let newClientSecret = null;
            let ready = false;
            let saving = false;
            let rotatingSecret = false;

            new QUIConfirm({
                title    : QUILocale.get(lg, 'control.user.clients.window.edit.title', {
                    clientId: data.client_id
                }),
                icon     : 'fa fa-edit',
                maxHeight: 600,
                maxWidth : 1000,
                autoclose: false,
                events   : {
                    onOpen: (Win) => {
                        const Content = Win.getContent();

                        Win.Loader.show();
                        Content.replaceChildren();

                        OAuthServer.getClient(data.client_id).then((clientData) => {
                            const lgPrefix = 'controls.backend.UserClients.createClient.template.';
                            const authorization = clientData.authorization;

                            canEditAuthorization = authorization?.editable === true;

                            Win.setContent(Mustache.render(templateEdit, {
                                ...getAuthorizationLabels(),
                                labelClientId                 : QUILocale.get(lg, 'client_id'),
                                labelClientSecret             : QUILocale.get(lg, 'client_secret'),
                                labelName                     : QUILocale.get('quiqqer/core', 'name'),
                                labelCDate                    : QUILocale.get('quiqqer/core', 'c_date'),
                                labelScopeSettings            : QUILocale.get(lg, lgPrefix + 'labelScopeSettings'),
                                labelButtonGenerateSecret     : QUILocale.get(lg, lgPrefix + 'labelButtonGenerateSecret'),
                                labelClientSecretIsToken      : QUILocale.get(lg, lgPrefix + 'labelClientSecretIsToken'),
                                descriptionClientSecretIsToken: QUILocale.get(lg, lgPrefix + 'descriptionClientSecretIsToken'),
                                textClientSecretIsToken       : QUILocale.get(lg, lgPrefix + 'textClientSecretIsToken'),
                                clientId                      : clientData.client_id,
                                clientSecret                  : clientData.client_secret ?? '',
                                name                          : clientData.name,
                                c_date                        : new Date(clientData.c_date * 1000).toISOString(),
                                canRotateSecret               : clientData.token_endpoint_auth_method !== 'none',
                                authorization                 : authorization && {
                                    editable: canEditAuthorization,
                                    redirectUris: authorization.redirectUris.join('\n'),
                                    resources: authorization.resources.join('\n')
                                }
                            }));

                            const SecretIsToken = Content.querySelector('[data-name="secret-is-token"]');
                            const RotateSecret = Content.querySelector('[data-name="rotate-secret"]');

                            if (SecretIsToken) {
                                SecretIsToken.checked = Number(clientData.client_secret_is_token) === 1;
                            }

                            RotateSecret?.addEventListener('click', async () => {
                                if (saving || rotatingSecret) {
                                    return;
                                }

                                rotatingSecret = true;
                                RotateSecret.disabled = true;

                                try {
                                    newClientSecret = await OAuthServer.generateClientSecret();
                                    Content.querySelector('[data-name="client-secret"]').textContent = newClientSecret;
                                } catch (error) {
                                    showSaveError(Content, error);
                                } finally {
                                    rotatingSecret = false;
                                    RotateSecret.disabled = false;
                                }
                            });

                            ScopeSettingsControl = new ScopeSettings({
                                clientId: data.client_id,
                                settings: clientData.scope_restrictions,
                                events  : {
                                    onLoaded: function (Control) {
                                        Control.getElm().classList.add('field-container-field');
                                        ready = true;
                                        Win.Loader.hide();
                                    }
                                }
                            }).inject(
                                Content.querySelector('[data-name="scope-settings"]')
                            );
                        }).catch(() => {
                            Win.Loader.hide();
                        });
                    },

                    onSubmit: async (Win) => {
                        if (!ready || saving || rotatingSecret) {
                            return;
                        }

                        const Content = Win.getContent();
                        const clientSettings = {
                            title: Content.querySelector('[data-name="client-name"]').value,
                            scope_restrictions: ScopeSettingsControl.getSettings(),
                            clientSecretIsToken: Content.querySelector('[data-name="secret-is-token"]')?.checked ?? false,
                            clientSecret: newClientSecret
                        };

                        if (canEditAuthorization) {
                            clientSettings.authorization = readAuthorizationSettings(Content);
                        }

                        saving = true;
                        Content.querySelector('[data-name="dialog-error"]').textContent = '';
                        Win.Loader.show();

                        try {
                            await OAuthServer.updateClient(data.client_id, clientSettings);
                        } catch (error) {
                            showSaveError(Content, error);
                            saving = false;
                            Win.Loader.hide();
                            return;
                        }

                        Win.close();
                        this.refresh();
                    }
                }
            }).open();
        }
    });
});

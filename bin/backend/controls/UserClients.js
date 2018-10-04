/**
 * Manage OAuth2 clients for a QUIQQER user
 *
 * @module package/quiqqer/oauth-server/bin/backend/controls/UserClients
 * @author www.pcsg.de (Patrick Müller)
 */
define('package/quiqqer/oauth-server/bin/backend/controls/UserClients', [

    'qui/QUI',
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

], function (QUI, QUIControl, QUIConfirm, QUIPoup, QUIButton, QUILoader, ScopeSettings, OAuthServer, Grid,
             QUILocale, Mustache, templateCreate, templateEdit) {
    "use strict";

    var lg = 'quiqqer/oauth-server';

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
                onInject: this.$onInject
            });
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
                    type: 'seperator'
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
                    text     : QUILocale.get(lg, 'control.user.clients.button.delete'),
                    textimage: 'fa fa-trash',
                    disabled : true,
                    events   : {
                        onClick: this.openDeleteDialog
                    }
                }],
                columnModel: [{
                    header   : QUILocale.get('quiqqer/system', 'name'),
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
                    var selected = self.$Grid.getSelectedIndices(),
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
            var self = this;
            var ScopeSettingsControl;

            return new Promise(function (resolve) {
                var Popup = new QUIPoup({
                    icon           : 'fa fa-plus',
                    title          : QUILocale.get(
                        lg, 'controls.backend.UserClient.createClient.popup.title'
                    ),
                    maxHeight      : 600,
                    maxWidth       : 1000,
                    closeButtonText: QUILocale.get(lg, 'controls.backend.UserClient.createClient.popup.close.text'),
                    events         : {
                        onOpen : function (Popup) {
                            var lgPrefix = 'controls.backend.UserClients.createClient.template.',
                                Content  = Popup.getContent();

                            Popup.setContent(Mustache.render(templateCreate, {
                                labelName         : QUILocale.get(lg, lgPrefix + 'labelName'),
                                labelScopeSettings: QUILocale.get(lg, lgPrefix + 'labelScopeSettings')
                            }));

                            Popup.Loader.show();

                            ScopeSettingsControl = new ScopeSettings({
                                events: {
                                    onLoaded: function (Control) {
                                        Control.getElm().addClass('field-container-field');
                                        Popup.Loader.hide();
                                        self.refresh();
                                    }
                                }
                            }).inject(
                                Content.getElement('.scope-settings')
                            );

                            Content.getElement('input[name="name"]').focus();
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
                        onClick: function () {
                            var Content = Popup.getContent();

                            Popup.Loader.show();

                            OAuthServer.createClient(
                                self.getAttribute('User').getId(),
                                ScopeSettingsControl.getSettings(),
                                Content.getElement('input[name="name"]').value
                            ).then(function () {
                                Popup.close();
                                self.refresh();
                            }, function () {
                                Popup.Loader.hide();
                            });
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
            var ScopeSettingsControl;
            var self = this,
                data = this.$Grid.getSelectedData()[0];

            new QUIConfirm({
                title    : QUILocale.get(lg, 'control.user.clients.window.edit.title', {
                    clientId: data.client_id
                }),
                icon     : 'fa fa-edit',
                maxHeight: 600,
                maxWidth : 1000,
                events   : {
                    onOpen: function (Win) {
                        var Content = Win.getContent();

                        Win.Loader.show();
                        Content.set('html', '');

                        OAuthServer.getClient(data.client_id).then(function (clientData) {
                            var lgPrefix = 'controls.backend.UserClients.createClient.template.';

                            Content.set('html', Mustache.render(templateEdit, {
                                labelClientId     : QUILocale.get(lg, 'client_id'),
                                labelClientSecret : QUILocale.get(lg, 'client_secret'),
                                labelName         : QUILocale.get('quiqqer/system', 'name'),
                                labelCDate        : QUILocale.get('quiqqer/system', 'c_date'),
                                labelScopeSettings: QUILocale.get(lg, lgPrefix + 'labelScopeSettings'),
                                clientId          : clientData.client_id,
                                clientSecret      : clientData.client_secret.trim(),
                                name              : clientData.name,
                                c_date            : new Date(parseInt(clientData.c_date * 1000)).toISOString()
                            }));

                            ScopeSettingsControl = new ScopeSettings({
                                clientId: data.client_id,
                                settings: clientData.scope_restrictions,
                                events  : {
                                    onLoaded: function (Control) {
                                        Control.getElm().addClass('field-container-field');
                                        Win.Loader.hide();
                                    }
                                }
                            }).inject(
                                Content.getElement('.scope-settings')
                            );
                        });
                    },

                    onSubmit: function (Win) {
                        var Content = Win.getContent();

                        Win.Loader.show();

                        OAuthServer.updateClient(data.client_id, {
                            title             : Content.getElement('[name="name"]').value,
                            scope_restrictions: ScopeSettingsControl.getSettings()
                        }).then(function () {
                            return self.refresh();
                        }).then(function () {
                            Win.close();
                        }).catch(function (Exception) {
                            QUI.getMessageHandler().then(function (MH) {
                                MH.addException(Exception);
                            });

                            Win.Loader.hide();
                        });
                    }
                }
            }).open();
        }
    });
});

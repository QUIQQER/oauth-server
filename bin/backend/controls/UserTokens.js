/**
 * Manage permanent API tokens for a QUIQQER user
 *
 * @module package/quiqqer/oauth-server/bin/backend/controls/UserTokens
 */
define('package/quiqqer/oauth-server/bin/backend/controls/UserTokens', [

    'qui/QUI',
    'qui/controls/Control',
    'qui/controls/windows/Confirm',
    'qui/controls/windows/Popup',
    'qui/controls/buttons/Button',
    'qui/controls/loader/Loader',

    'package/quiqqer/oauth-server/bin/backend/OAuthServer',

    'controls/grid/Grid',
    'Locale',
    'Mustache',

    'text!package/quiqqer/oauth-server/bin/backend/controls/UserTokens.Create.html'

], function (QUI, QUIControl, QUIConfirm, QUIPopup, QUIButton, QUILoader, OAuthServer, Grid, QUILocale, Mustache, templateCreate) {
    "use strict";

    var lg = 'quiqqer/oauth-server';

    return new Class({

        Extends: QUIControl,
        Type   : 'package/quiqqer/oauth-server/bin/backend/controls/UserTokens',

        Binds: [
            'refresh',
            'createToken',
            'openDeleteDialog',
            '$getUser'
        ],

        options: {
            User: false
        },

        initialize: function (options) {
            this.parent(options);

            this.$Grid = null;
            this.Loader = new QUILoader();
            this.$User = null;

            this.addEvents({
                onInject: this.$onInject
            });
        },

        /**
         * Event: on inject
         */
        $onInject: function () {
            var self = this,
                Elm = this.getElm();

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
                    text     : QUILocale.get(lg, 'control.user.tokens.button.add'),
                    textimage: 'fa fa-plus',
                    events   : {
                        onClick: function (Btn) {
                            Btn.setAttribute('textimage', 'fa fa-spinner fa-spin');
                            self.createToken().then(function () {
                                Btn.setAttribute('textimage', 'fa fa-plus');
                            });
                        }
                    }
                }, {
                    name     : 'delete',
                    text     : '',
                    icon     : 'fa fa-trash',
                    title    : QUILocale.get(lg, 'control.user.tokens.button.delete'),
                    position : 'right',
                    disabled : true,
                    events   : {
                        onClick: this.openDeleteDialog
                    }
                }],
                columnModel: [{
                    header   : QUILocale.get(lg, 'profile.tokens.label.title'),
                    dataIndex: 'title',
                    dataType : 'string',
                    width    : 220
                }, {
                    header   : QUILocale.get(lg, 'profile.tokens.title'),
                    dataIndex: 'token',
                    dataType : 'string',
                    width    : 500
                }, {
                    header   : QUILocale.get('quiqqer/system', 'c_date'),
                    dataIndex: 'createDate',
                    dataType : 'string',
                    width    : 180
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
                        TableButtons.delete.enable();
                    } else {
                        TableButtons.delete.disable();
                    }
                }
            });

            this.Loader.inject(Elm);

            this.refresh();
        },

        /**
         * Refresh token list
         *
         * @returns {Promise}
         */
        refresh: function () {
            var self = this;

            this.Loader.show();

            return this.$getUser().then(function (User) {
                return OAuthServer.getTokenList(User.getId());
            }).then(function (result) {
                self.$Grid.setData({
                    data: result
                });

                self.Loader.hide();
            }).catch(function (Exception) {
                QUI.getMessageHandler().then(function (MH) {
                    MH.addException(Exception);
                });

                self.Loader.hide();
            });
        },

        /**
         * Get user object from parent panel.
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
         * Open create token popup.
         *
         * @returns {Promise}
         */
        createToken: function () {
            var self = this;

            return new Promise(function (resolve) {
                var Popup = new QUIPopup({
                    icon           : 'fa fa-key',
                    title          : QUILocale.get(lg, 'control.user.tokens.window.create.title'),
                    maxHeight      : 260,
                    maxWidth       : 600,
                    closeButtonText: QUILocale.get(lg, 'controls.backend.UserClient.createClient.popup.close.text'),
                    events         : {
                        onOpen : function (Popup) {
                            Popup.setContent(Mustache.render(templateCreate, {
                                labelTitle      : QUILocale.get(lg, 'profile.tokens.label.title'),
                                placeholderTitle: QUILocale.get(lg, 'profile.tokens.placeholder.title')
                            }));

                            Popup.getContent().getElement('input[name="title"]').focus();
                        },
                        onClose: function () {
                            resolve();
                        }
                    }
                });

                Popup.open();

                Popup.addButton(new QUIButton({
                    text  : QUILocale.get(lg, 'profile.tokens.btn.create'),
                    alt   : QUILocale.get(lg, 'profile.tokens.btn.create'),
                    title : QUILocale.get(lg, 'profile.tokens.btn.create'),
                    events: {
                        onClick: function () {
                            var Content = Popup.getContent(),
                                title = Content.getElement('input[name="title"]').value;

                            Popup.Loader.show();

                            OAuthServer.createToken(
                                self.getAttribute('User').getId(),
                                title
                            ).then(function (result) {
                                if (!result || !result.id) {
                                    Popup.Loader.hide();
                                    return;
                                }

                                Popup.close();
                                return self.refresh();
                            }).catch(function (Exception) {
                                QUI.getMessageHandler().then(function (MH) {
                                    MH.addException(Exception);
                                });

                                Popup.Loader.hide();
                            });
                        }
                    }
                }));
            });
        },

        /**
         * Opens the delete dialog.
         */
        openDeleteDialog: function () {
            var self = this,
                data = this.$Grid.getSelectedData()[0];

            new QUIConfirm({
                title      : QUILocale.get(lg, 'control.user.tokens.window.delete.title'),
                text       : QUILocale.get(lg, 'control.user.tokens.window.delete.title'),
                information: QUILocale.get(lg, 'control.user.tokens.window.delete.text', {
                    title: data.title
                }),
                icon       : 'fa fa-trash',
                texticon   : 'fa fa-trash',
                maxWidth   : 600,
                maxHeight  : 400,
                autoclose  : false,
                events     : {
                    onSubmit: function (Win) {
                        Win.Loader.show();

                        OAuthServer.deleteToken(data.id).then(function (result) {
                            if (!result) {
                                Win.Loader.hide();
                                return false;
                            }

                            return self.refresh();
                        }).then(function (refreshed) {
                            if (refreshed === false) {
                                return;
                            }

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

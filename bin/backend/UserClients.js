/**
 * @module package/quiqqer/oauth-server/bin/backend/UserClients
 *
 * @require qui/QUI
 * @require qui/controls/Control
 * @require qui/controls/windows/Confirm
 * @require controls/grid/Grid
 * @require Ajax
 * @require Locale
 * @require Mustache
 * @require text!package/quiqqer/oauth-server/bin/backend/UserClients.Client.html
 */
define('package/quiqqer/oauth-server/bin/backend/UserClients', [

    'qui/QUI',
    'qui/controls/Control',
    'qui/controls/windows/Confirm',

    'controls/grid/Grid',
    'Ajax',
    'Locale',
    'Mustache',

    'text!package/quiqqer/oauth-server/bin/backend/UserClients.Client.html',
    'css!package/quiqqer/oauth-server/bin/backend/UserClients.css'

], function (QUI, QUIControl, QUIConfirm, Grid, QUIAjax, QUILocale, Mustache, templateClient) {
    "use strict";

    var lg = 'quiqqer/oauth-server';

    return new Class({

        Extends: QUIControl,
        Type: 'package/quiqqer/oauth-server/bin/backend/UserClients',

        Binds: [
            'refresh',
            'createClient',
            'openDeleteDialog',
            'openEditDialog'
        ],

        initialize: function (options) {
            this.parent(options);

            this.$Grid = null;

            this.addEvents({
                onInject: this.$onInject
            });
        },

        /**
         * event: on inject
         */
        $onInject: function () {
            var self = this,
                Elm = this.getElm();

            var Container = new Element('div', {
                styles: {
                    height: '100%',
                    width: '100%'
                }
            }).inject(Elm);


            var PanelContent = Elm.getParent('.qui-panel-content');

            this.$Grid = new Grid(Container, {
                pagination: true,
                buttons: [{
                    name: 'add',
                    text: QUILocale.get(lg, 'control.user.clients.button.add'),
                    textimage: 'fa fa-plus',
                    events: {
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
                    name: 'edit',
                    text: QUILocale.get(lg, 'control.user.clients.button.edit'),
                    textimage: 'fa fa-edit',
                    disabled: true,
                    events: {
                        onClick: this.openEditDialog
                    }
                }, {
                    name: 'delete',
                    text: QUILocale.get(lg, 'control.user.clients.button.delete'),
                    textimage: 'fa fa-trash',
                    disabled: true,
                    events: {
                        onClick: this.openDeleteDialog
                    }
                }],
                columnModel: [{
                    header: QUILocale.get('quiqqer/system', 'name'),
                    dataIndex: 'name',
                    dataType: 'string',
                    width: 200
                }, {
                    header: QUILocale.get(lg, 'client_id'),
                    dataIndex: 'client_id',
                    dataType: 'string',
                    width: 400
                }]
            });

            this.$Grid.setHeight(
                PanelContent.getSize().y - 40
            );

            this.$Grid.addEvents({
                onRefresh: this.refresh,
                onClick: function () {
                    var selected = self.$Grid.getSelectedIndices(),

                        Edit = self.$Grid.getButtons().filter(function (Btn) {
                            return Btn.getAttribute('name') == 'edit';
                        })[0],

                        Delete = self.$Grid.getButtons().filter(function (Btn) {
                            return Btn.getAttribute('name') == 'delete';
                        })[0];

                    Edit.enable();
                    Delete.enable();
                },
                onDblClick: this.openEditDialog
            });

            this.refresh();
        },

        /**
         * Refresh the list
         *
         * @returns {Promise}
         */
        refresh: function () {
            var self = this;
            return new Promise(function (resolve) {
                QUIAjax.get('package_quiqqer_oauth-server_ajax_client_list', function (result) {
                    self.$Grid.setData({
                        data: result
                    });

                    resolve();
                }, {
                    'package': 'quiqqer/oauth-server'
                });
            });
        },

        /**
         * Create a new client
         *
         * @returns {Promise}
         */
        createClient: function () {
            var self = this;

            return new Promise(function (resolve) {
                QUIAjax.post('package_quiqqer_oauth-server_ajax_client_create', function (result) {
                    self.refresh();
                    resolve(result);
                }, {
                    'package': 'quiqqer/oauth-server'
                });
            });
        },

        /**
         * Delete a client
         *
         * @param {String} clientId - ID of the client
         * @returns {Promise}
         */
        deleteClient: function (clientId) {
            var self = this;

            return new Promise(function (resolve) {
                QUIAjax.post('package_quiqqer_oauth-server_ajax_client_remove', function (result) {
                    self.refresh();
                    resolve(result);
                }, {
                    'package': 'quiqqer/oauth-server',
                    clientId: clientId
                });
            });
        },

        /**
         * Return the client data
         *
         * @param {String} clientId - ID of the client
         * @returns {Promise}
         */
        getClient: function (clientId) {
            var self = this;

            return new Promise(function (resolve, reject) {
                QUIAjax.get('package_quiqqer_oauth-server_ajax_client_get', resolve, {
                    'package': 'quiqqer/oauth-server',
                    clientId: clientId,
                    onError: reject
                });
            });
        },

        /**
         * Delete a Client
         *
         * @param {String} clientId - ID of the client
         * @param {Object} data - New data for the client
         * @returns {Promise}
         */
        updateClient: function (clientId, data) {
            return new Promise(function (resolve, reject) {
                QUIAjax.post('package_quiqqer_oauth-server_ajax_client_update', resolve, {
                    'package': 'quiqqer/oauth-server',
                    clientId: clientId,
                    data: JSON.encode(data),
                    onError: reject
                });
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
                title: QUILocale.get(lg, 'control.user.clients.window.delete.title'),
                icon: 'fa fa-trash',
                maxWidth: 600,
                maxHeight: 400,
                autoclose: false,
                events: {
                    onOpen: function (Win) {
                        var Content = Win.getContent();

                        Content.set('html', QUILocale.get(lg, 'control.user.clients.window.delete.text', {
                            name: data.name,
                            clientId: data.client_id
                        }));
                    },

                    onSubmit: function (Win) {
                        Win.Loader.show();

                        self.deleteClient(data.client_id).then(function () {
                            return self.refresh();
                        }).then(function () {
                            Win.close();
                        });
                    }
                }
            }).open();
        },

        /**
         * Opens the edit dialog
         */
        openEditDialog: function () {
            var self = this,
                data = this.$Grid.getSelectedData()[0];

            new QUIConfirm({
                title: QUILocale.get(lg, 'control.user.clients.window.edit.title', {
                    clientId: data.client_id
                }),
                icon: 'fa fa-edit',
                maxWidth: 600,
                maxHeight: 400,
                events: {
                    onOpen: function (Win) {
                        var Content = Win.getContent();

                        Win.Loader.show();
                        Content.set('html', '');

                        self.getClient(data.client_id).then(function (clientData) {

                            console.log(clientData);

                            Content.set('html', Mustache.render(templateClient, {
                                textClientId: QUILocale.get(lg, 'client_id'),
                                textClientSecret: QUILocale.get(lg, 'client_secret'),
                                textName: QUILocale.get('quiqqer/system', 'name'),
                                textCDate: QUILocale.get('quiqqer/system', 'c_date'),
                                clientId: clientData.client_id,
                                clientSecret: clientData.client_secret.trim(),
                                name: clientData.name,
                                c_date: new Date(parseInt(clientData.c_date * 1000)).toISOString()
                            }));

                            Win.Loader.hide();
                        });
                    },

                    onSubmit: function (Win) {
                        var Content = Win.getContent();

                        Win.Loader.show();

                        self.updateClient(data.client_id, {
                            name: Content.getElement('[name="name"]').value
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

/**
 * @module package/quiqqer/oauth-server/bin/backend/UserClients
 *
 * @require qui/QUI
 * @require qui/controls/Control
 * @require qui/controls/windows/Confirm
 * @require controls/grid/Grid
 * @require Ajax
 * @require Locale
 */
define('package/quiqqer/oauth-server/bin/backend/UserClients', [

    'qui/QUI',
    'qui/controls/Control',
    'qui/controls/windows/Confirm',

    'controls/grid/Grid',
    'Ajax',
    'Locale'

], function (QUI, QUIControl, QUIConfirm, Grid, QUIAjax, QUILocale) {
    "use strict";

    var lg = 'quiqqer/oauth-server';

    return new Class({

        Extends: QUIControl,
        Type: 'package/quiqqer/oauth-server/bin/backend/UserClients',

        Binds: [
            'refresh',
            'createClient',
            'openDeleteDialog'
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
                    width: 100
                }, {
                    header: QUILocale.get(lg, 'control.user.clients.header.client_id'),
                    dataIndex: 'client_id',
                    dataType: 'string',
                    width: 400
                }]
            });

            this.$Grid.setHeight(
                PanelContent.getSize().y - 20
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
         * Create a new Client
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
         * Delete a Client
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
         *
         */
        openEditDialog: function () {

        }
    });
});

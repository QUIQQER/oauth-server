/**
 * @module package/quiqqer/oauth-server/bin/backend/UserClients
 *
 * @require qui/QUI
 * @require qui/controls/Control
 */
define('package/quiqqer/oauth-server/bin/backend/UserClients', [

    'qui/QUI',
    'qui/controls/Control',

    'controls/grid/Grid',
    'Ajax',
    'Locale'

], function (QUI, QUIControl, Grid, QUIAjax, QUILocale) {
    "use strict";

    var lg = 'quiqqer/oauth-server';

    return new Class({

        Extends: QUIControl,
        Type: 'package/quiqqer/oauth-server/bin/backend/UserClients',

        Binds: [
            'refresh',
            'createClient'
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
                    text: 'Client hinzufügen',
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
                    text: 'Client editieren',
                    textimage: 'fa fa-edit',
                    disabled: true
                }, {
                    text: 'Client löschen',
                    textimage: 'fa fa-trash',
                    disabled: true
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
                onRefresh: this.refresh
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
        }
    });
});

/**
 * @module package/quiqqer/oauth-server/bin/backend/UserClients
 *
 * @require qui/QUI
 * @require qui/controls/Control
 */
define('package/quiqqer/oauth-server/bin/backend/UserClients', [

    'qui/QUI',
    'qui/controls/Control',

    'controls/grid/Grid'

], function (QUI, QUIControl, Grid) {
    "use strict";

    return new Class({

        Extends: QUIControl,
        Type: 'package/quiqqer/oauth-server/bin/backend/UserClients',

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
            var Elm = this.getElm();
            var Container = new Element('div', {
                styles: {
                    height: '100%',
                    width: '100%'
                }
            }).inject(Elm);

            var PanelContent = Elm.getParent('.qui-panel-content');

            this.$Grid = new Grid(Container, {
                buttons: [{
                    text: 'Client hinzufügen'
                }, {
                    text: 'Client editieren'
                }, {
                    text: 'Client löschen'
                }],
                columnModel: []
            });

            this.$Grid.setHeight(
                PanelContent.getSize().y - 20
            );
        }
    });
});

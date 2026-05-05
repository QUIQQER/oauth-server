define('package/quiqqer/oauth-server/bin/frontend/controls/profile/Tokens', [
    'qui/QUI',
    'qui/controls/Control',
    'Ajax',
    'qui/controls/windows/SimpleConfirmWindow',
    'Locale'
], function (QUI, QUIControl, QUIAjax, SimpleConfirmWindow, QUILocale) {
    'use strict';

    var lg = 'quiqqer/oauth-server';

    return new Class({
        Extends: QUIControl,
        Type: 'package/quiqqer/oauth-server/bin/frontend/controls/profile/Tokens',

        Binds: [
            '$onImport',
            '$reloadProfileSetting',
            '$toggleTokenVisibility',
            '$showError',
            '$confirmDelete'
        ],

        initialize: function (options) {
            this.parent(options);

            this.addEvents({
                onImport: this.$onImport
            });
        },

        $onImport: function () {
            var self = this;
            var Elm = this.getElm();
            var titleInput = Elm.getElement('input[name="tokenTitle"]');
            var createBtn = Elm.getElement('[data-role="create-token"]');
            var deleteButtons = Elm.getElements('[data-role="delete-token"]');
            var toggleButtons = Elm.getElements('[data-role="toggle-token-visibility"]');

            if (createBtn) {
                createBtn.addEvent('click', function (event) {
                    event.preventDefault();

                    self.$save({
                        oauthTokenAction: 'create',
                        tokenTitle: titleInput ? titleInput.value : ''
                    });
                });
            }

            deleteButtons.addEvent('click', function (event) {
                event.preventDefault();
                self.$confirmDelete(this.get('data-token-id'));
            });

            toggleButtons.addEvent('click', this.$toggleTokenVisibility);
        },

        $toggleTokenVisibility: function (event) {
            event.preventDefault();

            var Button = event.target;

            if (Button.nodeName !== 'BUTTON') {
                Button = Button.getParent('button');
            }

            if (!Button) {
                return;
            }

            var Row = Button.getParent('.quiqqer-oauth-server-profile-tokens-tokenRow');
            var TokenValue = Row ? Row.getElement('[data-role="token-value"]') : null;

            if (!TokenValue) {
                return;
            }

            var isHidden = TokenValue.get('data-token-hidden') === '1';
            var token = TokenValue.get('data-token-value') || '';
            var icon = Button.getElement('.fa');
            var showText = Button.get('data-show-text') || '';
            var hideText = Button.get('data-hide-text') || '';

            if (isHidden) {
                TokenValue.set('text', token);
                TokenValue.set('data-token-hidden', '0');
                Button.set('title', hideText);
                Button.set('aria-label', hideText);

                if (icon) {
                    icon.removeClass('fa-eye');
                    icon.addClass('fa-eye-slash');
                }

                return;
            }

            TokenValue.set('text', '••••••••••••••••••••••••••••••••••••••••');
            TokenValue.set('data-token-hidden', '1');
            Button.set('title', showText);
            Button.set('aria-label', showText);

            if (icon) {
                icon.removeClass('fa-eye-slash');
                icon.addClass('fa-eye');
            }
        },

        $save: function (data) {
            var self = this;

            QUIAjax.post('package_quiqqer_frontend-users_ajax_frontend_profile_save', function () {
                self.$reloadProfileSetting();
            }, {
                'package': 'quiqqer/frontend-users',
                category: 'user',
                settings: 'oauthTokens',
                data: JSON.encode(data),
                onError: function (error) {
                    self.$showError(error);
                }
            });
        },

        $showError: function (error) {
            var message = 'An unexpected error occurred.';

            if (error) {
                if (typeof error.getMessage === 'function') {
                    message = error.getMessage();
                } else if (error.message) {
                    message = error.message;
                } else if (typeof error === 'string') {
                    message = error;
                }
            }

            QUI.getMessageHandler().then(function (MH) {
                MH.addError(message);
            });
        },

        $confirmDelete: function (tokenId) {
            if (!tokenId) {
                return;
            }

            new SimpleConfirmWindow({
                'class': 'quiqqer-oauth-server-profile-tokens-confirm',
                title: QUILocale.get(lg, 'profile.tokens.delete.confirm.title'),
                message: false,
                maxWidth: 480,
                maxHeight: 320,
                buttonCancel: {
                    text: QUILocale.get('quiqqer/quiqqer', 'cancel'),
                    icon: false,
                    'class': 'btn btn-link-body'
                },
                buttonSubmit: {
                    text: QUILocale.get(lg, 'profile.tokens.btn.delete'),
                    icon: 'fa fa-trash',
                    'class': 'btn btn-red'
                },
                events: {
                    onOpen: function (Popup) {
                        var Content = Popup.getContent();

                        Content.set('html', '' +
                            '<div class="quiqqer-oauth-server-profile-tokens-confirmContent default-content">' +
                            '   <div class="quiqqer-oauth-server-profile-tokens-confirmIcon">' +
                            '       <span class="fa fa-trash"></span>' +
                            '   </div>' +
                            '   <h1>' + QUILocale.get(lg, 'profile.tokens.delete.confirm.title') + '</h1>' +
                            '   <p>' + QUILocale.get(lg, 'profile.tokens.delete.confirm.text') + '</p>' +
                            '</div>'
                        );
                    },
                    onSubmit: function (Popup) {
                        Popup.close();
                    }
                }
            }).addEvent('submit', function () {
                this.$save({
                    oauthTokenAction: 'delete',
                    oauthTokenId: tokenId
                });
            }.bind(this)).open();
        },

        $reloadProfileSetting: function () {
            var Profile = this.getElm().getParent(
                '[data-qui="package/quiqqer/frontend-users/bin/frontend/controls/profile/Profile"]'
            );

            if (Profile && Profile.get('data-quiid')) {
                QUI.Controls.getById(Profile.get('data-quiid')).openSetting('user', 'oauthTokens', false);
                return;
            }

            window.location.reload();
        }
    });
});

/**
 * The main ui for the Email Notification
 */
Ext.define('App.pluggables.modules.Notification.apps.NewTestEmailNotification.Main', {
    extend: 'Ext.panel.Panel',
    alias: 'widget.pluggables_notification_newtestemailnotification_main',
    requires: [
        'App.pluggables.modules.Notification.apps.NewTestEmailNotification.view.Form'
    ],
    config: {
        appId: null,
        input: {}
    },
    initComponent: function () {
        this.layout = 'fit';
        this.items = [{
            itemId: 'list',
            xtype: 'pluggables_notification_newtestemailnotification_form',
            border: false,
            appId: this.getAppId(),
            input: this.getInput()
        }];
        this.callParent(arguments);
    }
});

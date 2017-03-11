Ext.define('App.pluggables.modules.Notification.apps.NewTestEmailNotification.view.Form', {
    extend: 'App.lib.Form',
    alias: 'widget.pluggables_notification_newtestemailnotification_form',
    requires: [
        'App.ui.form.field.BoxSelect', 'App.ui.LinkMenu'
    ],
    discardChanges: true,
    config: {
        appId: null,
        input: {}
    },
    initComponent: function () {
        var me = this,
            input = this.getInput();
        this.widgetParams = this.widgetParams || {};
        this.widgetParams = Ext.apply(this.widgetParams, {
        }, input);

        this.forceEditId = true;

        this.privateConfig = {
            submitUrl: 'pluggables/Notification/NewTestEmailNotification/create',
            dataUrl: 'pluggables/Notification/NewTestEmailNotification/extract'
        };
        this.items = [{
            xtype: 'fieldset',
            title: 'Notification: Email',
            defaults: {
                anchor: '0'
            },
            items: [
                {
                    xtype: 'checkboxfield',
                    boxLabel: 'Notify via email',
                    name: 'notify_newtestemail',
                    listeners: {
                        change: function(f, state) {
                            f.up('fieldset').down('*[name=email_emails]').setDisabled(!state)
                            f.up('fieldset').down('*[name=email_template]').setDisabled(!state)
                            if (!state) {
                                f.up('fieldset').down('*[name=email_threshold_enabled]').setValue(false)
                                f.up('fieldset').down('*[name=email_threshold_value]').setDisabled(true)
                                f.up('fieldset').down('*[name=email_threshold_option]').setDisabled(true)
                            }
                            f.up('fieldset').down('*[name=email_threshold_enabled]').setDisabled(!state)
                        }
                    }
                },
                {
                    xtype: 'boxselectfield',
                    name: 'email_emails',
                    storeAutoLoad: false,
                    addable: true,
                    growMax: 70,
                    allowBlank: false,
                    fieldLabel: 'Emails',
                    labelAlign: 'top',
                    disabled: true
                },
                {
                    xtype: 'htmleditor',
                    name: 'email_template',
                    fieldLabel: 'Message',
                    value: '',
                    height: 120,
                    labelAlign: 'top',
                    disabled: true
                },
                {
                    fieldLabel: 'Threshold',
                    name: 'email_threshold_enabled',
                    xtype: 'checkbox',
                    boxLabel: "After triggering once, don't trigger for",
                    disabled: true,
                    listeners: {
                        change: function(f, state) {
                            f.up('fieldset').down('*[name=email_threshold_value]').setDisabled(!state)
                            f.up('fieldset').down('*[name=email_threshold_option]').setDisabled(!state)
                        }
                    }
                },
                {
                    xtype: 'fieldcontainer',
                    layout: 'hbox',
                    hideEmptyLabel: false,
                    items: [
                        {
                            xtype: 'textfield',
                            width: 69,
                            name: 'email_threshold_value',
                            style: 'margin-right:10px',
                            allowBlank: false,
                            maskRe: /[0-9]+/,
                            disabled: true
                        },
                        {
                            xtype: 'combobox',
                            name: 'email_threshold_option',
                            allowBlank: false,
                            disabled: true,
                            value: 'minute',
                            editable: false,
                            store: [
                                ['minute', 'Minute(s)'],
                                ['hour', 'Hour(s)'],
                                ['day', 'Day(s)']
                            ]
                        }
                    ]
                }
            ]
        }];

        this.buttons = [{
            text: 'Save',
            name: 'submit'
        }, {
            text: 'Cancel',
            name: 'cancel'
        }];
        this.callParent(arguments);
    }
});

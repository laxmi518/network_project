/**
 * Form for syslog collector
 */
Ext.define('App.pluggables.modules.Collection.apps.RSSFetcher.views.Form', {
    extend: 'App.lib.Form',
    alias: 'widget.pluggables_collection_rssfetcher_form',
    requires: ['App.pluggables.modules.Collection.lib.Util'],
    bodyPadding: 10,
    width: 500,
    appTitle: 'RSS Fetcher',
    config: {
        appId: null
    },
    initComponent: function () {
        var util = App.pluggables.modules.Collection.lib.Util,
            normalizer = util.getComboBox('normalizer', 'Normalization Policy', 'Normalizers', 'None', 140),
            repo = util.getComboBox('repo', 'Repo', 'Repos', 'default', 140),
            charset = util.getComboBox('charset', 'Charset', 'Charset', 'utf_8', 140),
            input = App.pluggables.lib.Mixin.getAppInput(this.getAppId());

        this.widgetParams = this.widgetParams || {};
        this.widgetParams = Ext.apply(this.widgetParams, {
            id: true
        }, input);

        this.privateConfig = {
            submitUrl: 'pluggables/Collection/RSSFetcher/create',
            dataUrl: 'pluggables/Collection/RSSFetcher/extract'
        };
        this.items = [{
            xtype: 'fieldset',
            title: 'RSS Fetcher',
            defaults: {
                anchor: '0'
            },
            items: [{
                xtype: 'hiddenfield',
                name: 'app_name',
                value: 'RSSFetcher',
                allowBlank: false
            },{
                xtype: 'textfield',
                name: 'url',
                fieldLabel: 'RSS Url',
                allowBlank: false,
                labelWidth: 140
            },
            {
                xtype: 'textfield',
                name: 'interval',
                fieldLabel: 'Fetch Interval (minutes)',
                emptyText: 'in minutes',
                allowBlank: false,
                labelWidth: 140
            },
            parser, normalizer, repo, charset]
        }];

        this.buttons = [util.getDeleteButton({
            name: 'RSS Fetcher',
            input: input
        }), '->', util.getTestButton({
            name: 'RSS Fetcher',
            input: input
        }), {
            text: 'Submit',
            name: 'submit',
            afterSuccess: function (form, actions, formpanel) {
                util.reUpdateMain('pluggables_collection_rssfetcher_main');
            }
        }, {
            text: 'Cancel',
            name: 'cancel',
            handler: function () {

            }
        }];
        this.callParent(arguments);
    }
});

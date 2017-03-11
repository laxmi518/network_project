/**
 * List of added syslog collectors
 */
Ext.define('App.pluggables.modules.Collection.apps.RSSFetcher.views.List', {
    extend: 'App.lib.SwitchListView',
    alias: 'widget.pluggables_collection_rss_fetcher_list',
    store: Ext.create('App.pluggables.modules.Collection.apps.RSSFetcher.store.RSSFetcher'),
    multiselect: true,
    switchConfig: {
        box: true
    },
    initComponent: function () {
        this.privateConfig = {
            deleteUrl: '/pluggables/Collection/RSSFetcher/delete'
        };
        this.dockedItems = this.dockedItems || [];
        this.dockedItems.push({
            xtype: 'toolbar',
            defaults: {
                ui: 'plain'
            },
            items: [{
                text: 'Add',
                glyph: App.GM.get('plus-sign'),
                handler: function () {
                    var widget = Ext.widget('pluggables_collection_rssfetcher_form');
                    win = Ext.create('App.ui.HelpWindow', Ext.apply({
                        app: 'pluggables/Collection/RSSFetcher',
                        widget: widget,
                        title: widget.appTitle
                    }, {}));
                    win.show().center();
                }
            }]
        });

        this.moreActions = [
            {
                text: 'Delete Selected',
                action: 'delete-selected-savedsearch',
                identifier: 'User',
                permission: true,
                url: this.privateConfig.deleteUrl
            }
        ];

        //this.store = Ext.getStore('App.pluggables.modules.Collection.apps.SyslogCollector.store.Syslog');
        this.columns = [
            {
                text: 'Url',
                dataIndex: 'url',
                flex: 1
            },
            {
                text: 'Interval',
                dataIndex: 'interval',
                flex: 1
            },
            {
                text: 'Repo',
                dataIndex: 'repo',
                flex: 1
            },
            {
                text: 'Normalization Policy',
                dataIndex: 'policy',
                flex: 1
            },
            {
                text: 'Charset',
                dataIndex: 'charset',
                flex: 1
            }
        ];
        this.actions = [
            'edit',
            'delete'
        ];
        this.callParent(arguments);
    },
    afterItemDelete: function (record) {
        App.pluggables.lib.Mixin.reUpdateMain('pluggables_collection_main');
    }
});


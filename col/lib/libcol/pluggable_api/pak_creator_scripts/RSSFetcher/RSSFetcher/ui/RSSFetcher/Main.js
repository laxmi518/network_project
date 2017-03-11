/**
 * The main ui for the syslog collector
 */
Ext.define('App.pluggables.modules.Collection.apps.RSSFetcher.Main', {
    extend: 'App.pluggables.lib.Application',
    alias: 'widget.pluggables_collection_rssfetcher_main',
    requires: [
        'App.pluggables.modules.Collection.apps.RSSFetcher.model.RSSFetcher',
        'App.pluggables.modules.Collection.apps.RSSFetcher.store.RSSFetcher',
        'App.pluggables.modules.Collection.apps.RSSFetcher.views.List',
        'App.pluggables.modules.Collection.apps.RSSFetcher.views.Form'
    ],
    appTitle: 'RSS Fetcher',
    //showTitleBar: false,
    constructor: function () {
        this.callParent(arguments);
    },
    initComponent: function () {
        var me = this;
        App.pluggables.modules.Collection.lib.Util.openHelpForm({
            xtype: 'pluggables_collection_rssfetcher_form',
            app: 'pluggables/Collection/RSSFetcher',
            appId: me.getAppId()
        });
        this.callParent(arguments);
    }
});


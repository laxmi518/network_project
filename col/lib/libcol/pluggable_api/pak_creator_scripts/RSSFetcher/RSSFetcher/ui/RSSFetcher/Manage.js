/**
 * The manage ui for the syslog collector
 */
Ext.define('App.pluggables.modules.Collection.apps.RSSFetcher.Manage', {
    extend: 'App.pluggables.lib.Application',
    alias: 'widget.pluggables_collection_rssfetcher_manage',

    appTitle: 'RSS Fetcher Management',
    width: 500,
    height: 300,
    //showTitleBar: false,
    constructor: function () {
        this.callParent(arguments);
    },
    initComponent: function () {
        this.html = 'hello'
        this.callParent(arguments);
    }
});


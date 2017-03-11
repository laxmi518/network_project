#!/usr/bin/env python

import logging
import urlparse
import urllib2
import xml.sax
import feedparser

from libcol.interface.fetcher_runner import FetcherRunner
from libcol.interface.fetcher_interface import Fetcher

from resources.rss_exception import RssException, FaultTypes
from resources.rss_feedstatus import RssFeedStatus

class RssFetcher(Fetcher):

    class ProcessingStatus:
        (
        CreateEvent,
        ReFetch,
        Idle
        ) = range(3)

    def __init__(self, **args):
        super(RssFetcher, self).__init__(**args)
        self.etag = None
        self.modified = None

    def is_feed_protected(self):
        return True if hasattr(self, 'username') else False

    def passwordize(self):
        parts = list(urlparse.urlsplit(self.rss_url))
        parts[1] = self.username + ":" + self.password + "@" + parts[1]
        url = urlparse.urlunsplit(parts)
        return url

    def create_event(self, feed):
        '''
            Create event with title, published date and description, and,
            add it to the main event queue
        '''
        for entry in feed.entries:
            event = {}

            self.prepare_event(event, 'title', entry.title)
            self.prepare_event(event, 'posted', entry.published)
            self.prepare_event(event, 'msg', entry.description)

            self.add_event(event)

    def fetch_job(self):

        rss_url = self.passwordize(self.rss_url) if self.is_feed_protected() else self.rss_url
        try:
            feed = feedparser.parse(rss_url, etag=self.etag, modified=self.modified)
        except IOError, err:
            logging.error("IOError when loading feed %s, err=%s", self.rss_url, err)

        try:
            process_status = self.process_feed(feed)
            if process_status == RssFetcher.ProcessingStatus.CreateEvent:
                self.create_event(feed)

        except RssException, msg:
            logging.warn(msg)


    def process_feed(self, feed):
        if feed.status:
            if feed.status == RssFeedStatus.NoNewFeed:
                logging.warn("Feed %s hasn't changed, skipping" % self.rss_url)
                return RssFetcher.ProcessingStatus.Idle

            elif feed.status == RssFeedStatus.AuthenticationNeeded:
                raise RssException("Authentication needed; Url: %s Headers: %s" %
                        self.rss_url, feed.headers['www-athenticate'], FaultTypes.AUTHENTICATION_ERROR)

            elif feed.status == RssFeedStatus.FeedNotFound:
                raise RssException("Feed not Found; Url: %s" % self.rss_url, FaultTypes.FEED_NOT_FOUND)

            elif feed.status == RssFeedStatus.FeedPermanentlyDeleted:
                raise RssException("Feed Permanently Deleted; Url: %s doesn't exist" %
                        self.rss_url, FaultTypes.PERMANENTLY_DELETED_FEED)

            elif feed.status == RssFeedStatus.InternalServerException:
                raise RssException("Internal Server Exception; Url: %s" % self.rss_url, FaultTypes.INTERNAL_SERVER_EXCEPTION)

        else:
            logging.error("No Feed Status. Maybe URLError on feed %s", self.rss_url)

        if feed.bozo:
            ex = feed.bozo_exception
            if isinstance(ex, feedparser.NonXMLContentType):
                logging.error("NonXMLContentType")

            elif isinstance(ex, xml.sax._exceptions.SAXParseException):
                raise RssException("Error parsing feeds from Url: %s" % self.rss_url, FaultTypes.SAX_PARSER_EXCEPTION)

            elif isinstance(ex, urllib2.URLError):
                raise RssException("URLError", FaultTypes.URL_EXCEPTION)

            elif isinstance(ex, feedparser.CharacterEncodingOverride):
                logging.debug("[CharacterEncodingOverride] Adjusted CharacterEncoding Automatically")

            else:
                raise RssException("Unhandled boxo_exception; Type: %s.%s" %
                        ex.__class__.__module__, ex.__class__.__name__, FaultTypes.BOZO_EXCEPTION)

        try:
            self.etag = feed.etag
        except Exception:
            logging.warn("Etag not Returned by Server")
        try:
            self.modified = feed.modified
        except Exception:
            logging.warn("Last Modified not Returned by Server")

        if feed.status == RssFeedStatus.FeedTemporarilyMoved:
           logging.warn("Feed has Temporarily Moved to a New Location %s", feed.href)

        elif feed.status == RssFeedStatus.FeedPermanentlyMoved:
           logging.warn("Feed has Permanently Moved to %s, from %s", feed.href, self.rss_url)
           self.get_client_map()["rss_url"] = feed.href
           self.rss_url = feed.href

        else:
           logging.debug("Everything went well. Fetching feeds from %s", self.rss_url)

        return RssFetcher.ProcessingStatus.CreateEvent

runner = FetcherRunner()
runner.register_fetcher(RssFetcher)
runner.set_debug_mode(True)
runner.start()

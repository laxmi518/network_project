
from fetcher_runner import FetcherRunner
from fetcher_interface import Fetcher

class NewFetcher(Fetcher):

    def __init__(self, **args):
        super(NewFetcher, self).__init__(**args)
        self.init_mem()

    def init_mem(self):
        self.mem = 10

    def update_mem(self):
        self.mem += 10

    def fetch_job(self):
        event = {}
        self.prepare_event(event, "msg", "This is test message.")
        self.prepare_event(event, "mem", self.mem, "_type_num")
        #add this event to queue
        self.add_event(event)

        self.update_mem()

runner = FetcherRunner()
runner.register_fetcher(NewFetcher)
runner.start()

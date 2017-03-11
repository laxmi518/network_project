import logging
import gevent

class JobGenerator(object):

    def __init__(self, fetcher_runner):
        """
        It is a dict which contains {sid_name:runnig_fetchjob_instance}
        """
        self.fetcher_runner = fetcher_runner
        self.__running_jobs = {}

    def __run(self, sid, client_map, seconds, instance):

        while True:
            try:
                """
                New instance for each sid is created
                """
                instance.fetch_job()

            except gevent.GreenletExit:
                raise
            except Exception, err:
                logging.warn('exception while running job %s, error=%s', client_map, err)
            gevent.sleep(seconds)

    def __schedule(self, sid, client_map, interval, instance):
        return gevent.spawn_link_exception(self.__run, sid, client_map, interval, instance)


    def __update_jobs(self):
        """
        Parse config to update jobs
        Creates new job and kills old jobs not in config
        """

        for sid, client_map in self.fetcher_runner.get_config()['client_map'].iteritems():
            interval = client_map.get('fetch_interval') or 60

            old_job = self.__running_jobs.get(sid)

            if old_job:
                if old_job["client_map"] != client_map:
                    parser_changed = old_job["client_map"].get('parser') != client_map.get('parser')
                    old_job["instance"].set_fields(dict(sid=sid, client_map=client_map), parser_changed)
                if old_job['interval'] == interval:
                    continue
                else:
                    old_job['job'].kill()

            logging.debug('adding job for sid=%s', sid)

            instance = self.fetcher_runner.get_fetcher_handle()(
                            sid=sid,
                            client_map=client_map,
                            runner=self.fetcher_runner)
            job = self.__schedule(sid, client_map, interval, instance)
            self.__running_jobs[sid] = dict(job=job, interval=interval, client_map=client_map, instance=instance)

        # delete removed sources and kill their jobs
        # running_sid_jobs size may change during iteration so using .items()
        for sid, job in self.__running_jobs.items():
            if sid not in self.fetcher_runner.get_config()['client_map']:
                del self.__running_jobs[sid]
                job['job'].kill()


    def job_updater(self):
        """
        if config is changed, update jobs
        """
        while True:
            if self.fetcher_runner.get_config()['_onreload'](timeout = 1):
                self.__update_jobs()



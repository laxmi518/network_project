class Updater:
    def __init__(self, db, repo):
        self.db = db
        self.repo = repo

    def update_stat(self, status):
        self.db.datatransport.update({"repo": self.repo}, {"$set": {"status": status}})

    def get_col_ts(self):
        return self.db.datatransport.find_one({"repo": self.repo}).get("col_ts", 0)

    def save_col_ts(self, col_ts):
        self.db.datatransport.update({"repo": self.repo}, {"$set": {"col_ts": col_ts}})

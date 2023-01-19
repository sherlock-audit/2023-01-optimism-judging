import datetime
import os
import time
from functools import lru_cache, wraps

from github import Github, Issue, Repository
from github.GithubException import (
    GithubException,
    RateLimitExceededException,
    UnknownObjectException,
)

token = os.environ.get("GITHUB_TOKEN")
github = Github(token)


def github_retry_on_rate_limit(func):
    @wraps(func)
    def inner(*args, **kwargs):
        global github
        while True:
            try:
                return func(*args, **kwargs)
            except RateLimitExceededException:
                print("Rate Limit hit.")
                rl = github.get_rate_limit()
                time_to_sleep = (
                    rl.core.reset - datetime.datetime.utcnow()
                ).total_seconds()
                print("Sleeping for %s seconds" % time_to_sleep)
                time.sleep(time_to_sleep)

    return inner


class IssueExtended(Issue.Issue):
    @classmethod
    def cast(cls, issue: Issue):
        issue.__class__ = IssueExtended

        for func in ["edit"]:
            setattr(issue, func, github_retry_on_rate_limit(getattr(issue, func)))
        return issue


class RepositoryExtended(Repository.Repository):
    @classmethod
    def cast(cls, repo: Repository.Repository):
        repo.__class__ = RepositoryExtended

        for func in [
            "create_issue",
            "get_contents",
            "get_issue",
            "get_labels",
            "create_label",
        ]:
            setattr(repo, func, github_retry_on_rate_limit(getattr(repo, func)))
        return repo


# Issues list. Each issue is in the format:
# {
#   "id": 1,  # corresponds to the issue 001
#   "parent": 5,  # corresponds to the issue 005 => issue is duplicate of 005
#   "closed": True,  # True for a closed, unlabeled or low/info issue
#   "auditor": "rcstanciu",
#   "severity": "H",  # or None if the issue is unlabeled, closed or low/info
#   "title": "Issue title",
#   "body": "Issue body",
#   "has_duplicates": True,
# }
issues = {}


def process_directory(repo, path):
    global issues

    repo_items = [
        x
        for x in repo.get_contents(path)
        if x.name not in [".data", ".github", "README.md", "Audit_Report.pdf"]
    ]
    for item in repo_items:
        print("Reading file %s" % item.name)
        if item.name in ["low", "false"]:
            process_directory(repo, item.path)
            continue

        parent = None
        closed = any(x in path for x in ["low", "false"])
        files = []
        dir_issues_ids = []
        severity = None
        if item.type == "dir":
            # If it's a directory, we have some duplicate issues
            files = list(repo.get_contents(item.path))
            try:
                if not closed:
                    severity = item.name.split("-")[1]
            except Exception:
                pass
        else:
            # If it's a file, there is a solo issue
            files = [item]

        for file in files:
            if "best" in file.name:
                issue_id = int(file.name.replace("-best.md", ""))
                parent = issue_id
            else:
                issue_id = int(file.name.replace(".md", ""))

            body = file.decoded_content.decode("utf-8")
            auditor = body.split("\n")[0]
            title = auditor + " - " + body.split("\n")[4].split("# ")[1]
            if not severity:
                severity = body.split("\n")[2][0].upper()

            # Stop the script if an issue is found multiple times in the filesystem
            if issue_id in issues.keys():
                raise Exception("Issue %s found multiple times." % issue_id)

            issues[issue_id] = {
                "id": issue_id,
                "parent": None,
                "severity": severity,
                "body": body,
                "closed": closed,
                "auditor": auditor,
                "title": title,
                "has_duplicates": False,
            }
            dir_issues_ids.append(issue_id)

        # Set the parent field for all duplicates in this directory
        if len(files) > 1 and parent is None:
            raise Exception(
                "Issue %s does not have a primary file (-best.md)." % item.path
            )

        if parent:
            for issue_id in dir_issues_ids:
                if issue_id != parent:
                    issues[parent]["has_duplicates"] = True
                    issues[issue_id]["parent"] = parent
                    issues[issue_id]["closed"] = True


@lru_cache(maxsize=1024)
def get_github_issue(repo, issue_id):
    print("Fetching issue #%s" % issue_id)
    return IssueExtended.cast(repo.get_issue(issue_id))


def main():
    global issues
    global github

    repo = os.environ.get("GITHUB_REPOSITORY")
    run_number = int(os.environ.get("GITHUB_RUN_NUMBER"))

    repo = RepositoryExtended.cast(github.get_repo(repo))

    process_directory(repo, "")
    # Sort them by ID so we match the order
    # in which GitHub Issues created
    issues = dict(sorted(issues.items(), key=lambda item: item[1]["id"]))

    # Ensure issue IDs are sequential
    actual_issue_ids = list(issues.keys())
    expected_issue_ids = list(range(1, max(actual_issue_ids) + 1))
    missing_issue_ids = [x for x in expected_issue_ids if x not in actual_issue_ids]
    assert (
        actual_issue_ids == expected_issue_ids
    ), "Expected issues %s actual issues %s. Missing %s" % (
        expected_issue_ids,
        actual_issue_ids,
        missing_issue_ids,
    )

    labels = [
        {
            "name": "High",
            "color": "B60205",
            "description": "A valid High severity issue",
        },
        {
            "name": "Medium",
            "color": "D93F0B",
            "description": "A valid Medium severity issue",
        },
        {
            "name": "Low/Info",
            "color": "FBCA04",
            "description": "A valid Low/Informational severity issue",
        },
        {
            "name": "Has Duplicates",
            "color": "D4C5F9",
            "description": "A valid issue with 1+ other issues describing the same vulnerability",
        },
        {
            "name": "Duplicate",
            "color": "EDEDED",
            "description": "A valid issue that is a duplicate of an issue with `Has Duplicates` label",
        },
        {
            "name": "Sponsor Confirmed",
            "color": "1D76DB",
            "description": "The sponsor acknowledged this issue is valid",
        },
        {
            "name": "Sponsor Disputed",
            "color": "0E8A16",
            "description": "The sponsor disputed this issue's validity",
        },
        {
            "name": "Disagree With Severity",
            "color": "5319E7",
            "description": "The sponsor disputed the severity of this issue",
        },
        {
            "name": "Disagree With (non-)Duplication",
            "color": "F9D0C4",
            "description": "The sponsor disputed the duplication state of this issue",
        },
        {
            "name": "Will Fix",
            "color": "BFDADC",
            "description": "The sponsor confirmed this issue will be fixed",
        },
        {
            "name": "Escalated",
            "color": "FEF2C0",
            "description": "This issue contains a pending escalation",
        },
        {
            "name": "Escalation Resolved",
            "color": "71656E",
            "description": "This issue's escalations have been approved/rejected",
        },
        {
            "name": "Reward",
            "color": "91EB5F",
            "description": "A payout will be made for this issue",
        },
        {
            "name": "Non-Reward",
            "color": "C6D8CB",
            "description": "This issue will not receive a payout",
        },
        {
            "name": "Excluded",
            "color": "710E59",
            "description": "Excluded by the judge without consulting the protocol or the senior",
        },
    ]
    label_names = [x["name"] for x in labels]

    # Create the labels if it's the first time this action is run
    if run_number == 1:
        print("Creating issue labels")
        existing_labels = list(repo.get_labels())
        existing_label_names = [x.name for x in existing_labels]
        for label in existing_labels:
            if label.name not in label_names:
                label.delete()

        for label in labels:
            if label["name"] not in existing_label_names:
                repo.create_label(**label)
    else:
        print("Skipping creating labels.")

    # Sync issues
    for issue_id, issue in issues.items():
        print("Issue #%s" % issue_id)

        issue_labels = []
        if issue["has_duplicates"]:
            issue_labels.append("Has Duplicates")
        elif issue["parent"]:
            issue_labels.append("Duplicate")

        if not issue["closed"] or issue["parent"]:
            if issue["severity"] == "H":
                issue_labels.append("High")
            elif issue["severity"] == "M":
                issue_labels.append("Medium")

        if issue["closed"] and not issue["parent"]:
            issue_labels.append("Excluded")

        # Try creating/updating the issue until a success path is hit
        must_sleep = False
        while True:
            try:
                # Fetch existing issue
                gh_issue = get_github_issue(repo, issue_id)

                # We persist all labels except High/Medium/Has Duplicates/Duplicate
                existing_labels = [x.name for x in gh_issue.labels]
                new_labels = existing_labels.copy()
                if "High" in existing_labels:
                    new_labels.remove("High")
                if "Medium" in existing_labels:
                    new_labels.remove("Medium")
                if "Low" in existing_labels:
                    new_labels.remove("Low")
                if "Informational" in existing_labels:
                    new_labels.remove("Informational")
                if "Low/Info" in existing_labels:
                    new_labels.remove("Low/Info")
                if "Has Duplicates" in existing_labels:
                    new_labels.remove("Has Duplicates")
                if "Duplicate" in existing_labels:
                    new_labels.remove("Duplicate")
                if "Excluded" in existing_labels:
                    new_labels.remove("Excluded")
                new_labels = issue_labels + new_labels

                must_update = False
                if existing_labels != new_labels:
                    must_update = True
                    print(
                        "\tLabels differ. Old: %s New: %s"
                        % (existing_labels, new_labels)
                    )

                if gh_issue.title != issue["title"]:
                    must_update = True
                    print(
                        "\tTitles differ: Old: %s New: %s"
                        % (gh_issue.title, issue["title"])
                    )

                expected_body = (
                    issue["body"]
                    if not issue["parent"]
                    else issue["body"] + f"\n\nDuplicate of #{issue['parent']}\n"
                )
                if expected_body != gh_issue.body:
                    must_update = True
                    print("\tBodies differ. See the issue edit history for the diff.")

                if must_update:
                    print("\tIssue needs to be updated.")
                    gh_issue.edit(
                        title=issue["title"],
                        body=issue["body"],
                        state="closed" if issue["closed"] else "open",
                        labels=new_labels,
                    )
                    # Exit the inifite loop and sleep
                    must_sleep = True
                    break
                else:
                    print("\tIssue does not need to be updated.")
                    # Exit the infinite loop and don't sleep
                    # since we did not make any edits
                    break
            except UnknownObjectException:
                print("\tCreating issue")
                # Create issue - 1 API call
                gh_issue = repo.create_issue(
                    issue["title"], body=issue["body"], labels=issue_labels
                )
                if issue["closed"]:
                    gh_issue.edit(state="closed")

                # Exit the infinite loop and sleep
                must_sleep = True
                break

        # Sleep between issues if any edits/creations have been made
        if must_sleep:
            print("\tSleeping for 1 second...")
            time.sleep(1)

    print("Referencing parent issue from duplicate issues")
    duplicate_issues = {k: v for k, v in issues.items() if v["parent"]}
    # Set duplicate label
    for issue_id, issue in duplicate_issues.items():
        # Try updating the issue until a success path is hit
        must_sleep = False
        while True:
            try:
                print(
                    "\tReferencing parent issue %s from duplicate issue %s."
                    % (issue["parent"], issue_id)
                )

                # Fetch existing issue
                gh_issue = get_github_issue(repo, issue_id)
                expected_body = issue["body"] + f"\n\nDuplicate of #{issue['parent']}\n"

                if expected_body != gh_issue.body:
                    gh_issue.edit(
                        body=issue["body"] + f"\n\nDuplicate of #{issue['parent']}\n",
                    )
                    must_sleep = True
                else:
                    print("\t\tIssue %s does not need to be updated." % issue_id)

                # Exit the inifinite loop
                break

            except GithubException as e:
                print(e)

                # Sleep for 5 minutes (in case secondary limits have been hit)
                # Don't exit the inifite loop and try again
                time.sleep(300)

        # Sleep between issue updates
        if must_sleep:
            print("\t\tSleeping for 1 second...")
            time.sleep(1)


if __name__ == "__main__":
    main()

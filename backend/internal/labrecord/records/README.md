# Lab records

One JSON file per lab, written by the lab itself at the end of a run on a real AWS account
(`make public-access-lab-aws`, `make entrypoints-lab-aws`, `make boundary-lab-aws`) through
`scripts/lab-record.py`. Each holds, for every check, the
question, the referee AWS supplied, what AWS answered, what the engine said, and whether
they agreed - with the date, the Region and the engine version the run was made with.

They are built into the binary (`internal/labrecord`) and shown on the dashboard's Accuracy
page, so an instance shows how the rules of its own version were checked. Commit a record
only from a run you are willing to stand behind; a record with a disagreement is still a
record, and the page shows it as one. A record must never carry an AWS account ID: the
loader refuses a file with a twelve-digit number in it.

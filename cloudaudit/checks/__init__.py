"""Importing this package registers every check with ``Check.registry``."""

from . import cloudtrail, ec2, iam, s3  # noqa: F401

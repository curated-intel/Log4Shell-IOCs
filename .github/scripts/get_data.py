import re
from typing import BinaryIO
import unicodedata
from typing import Dict, List

import mistune
import pandas as pd
import requests
from bs4 import BeautifulSoup, Tag

DEFAULT_FOLDER = "CI_Log4Shell_Products"
DEFAULT_PREFIX = "Log4j_AffectedProducts"

STEPS = {
    "NCSC-NL": {
        "url": "https://git.io/JDDz6",
        "parser": "markdown",
        "kwargs": {
            "start_tag": "h3",
            "extract_links": ["Links"],
            "headers": [
                "Supplier",
                "Product",
                "Version",
                "Status CVE-2021-4104",
                "Status CVE-2021-44228",
                "Status CVE-2021-45046",
                "Status CVE-2021-45105",
                "Notes",
                "Links",
            ],
        },
    },
    "cisagov": {
        "url": "https://github.com/cisagov/log4j-affected-db/blob/develop/SOFTWARE-LIST.md",
        "parser": "markdown",
        "kwargs": {
            "start_tag": "h2",
            "extract_links": ["Vendor link"],
            "headers": [
                "Vendor",
                "Product",
                "Version(s)",
                "Status",
                "Update available",
                "Vendor link",
                "Notes",
                "Other References",
                "Last Updated",
            ],
        },
    },
    "swithak": {
        "url": "https://git.io/JD1zk",
        "parser": "regexp",
        "kwargs": {
            "pattern": r"##\s(?P<Product>[\w\s]+).*(?P<Source>https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b[-a-zA-Z0-9()!@:%_\+.~#?&\/\/=]*)",
        },
    },
}


def has_named_group(pattern: re.Pattern) -> bool:
    """Check if the pattern has capturing named groups.

    Args:
        pattern : Regular expression.

    Returns:
        bool: True if ``pattern`` has capturing named groups else False.
    """
    named_groups = r"\?[P]\<(?P<named_group>.+?)\>"
    matches = re.findall(named_groups, pattern)

    return bool(matches)


def extract_groupdict(ctx: str, pattern: re.Pattern) -> List[Dict]:
    """Extract capturing named groups from a string.

    Args:
        ctx (str): Source content to extract the capturing named groups from.
        pattern (re.Pattern): Regular expression.

    Returns:
        List[Dict]: List of the matching capturing groups as dictionary.
    """

    if has_named_group(pattern):
        ret = []
        for match in re.finditer(pattern, ctx):
            match = match.groupdict()
            if match:
                ret.append(match)
        return ret


def parse_tr_record(record: list, headers: list, extract_links: list) -> dict:
    """Parse table rows.

    Args:
        record (list): Table tr tag with each tds.
        headers (list): Headers of the table.
        extract_links (list): Column to extract href value.
    Returns:
        Dict: Parsed cells from record.
    """

    result = {}
    for index, header in enumerate(headers):
        hidx = [headers.index(col) for col in extract_links]
        if index in hidx:
            if len(record) in hidx:
                result[header] = {}
            else:
                links = {link.text: link.get("href") for link in record[index].find_all("a")}
                # result[header] = ", ".join([link for link in links])
                result[header] = links
        else:
            result[header] = unicodedata.normalize("NFKD", record[index].text)
    return result


def df_from_regexp(ctx: str, pattern: re.Pattern) -> pd.DataFrame:
    """Build a dataframe from ``extract_groupdict``.

    Args:
        ctx (str): Source content to extract the capturing named groups from.
        pattern (re.Pattern): Regular expression.

    Returns:
        pd.DataFrame
    """

    return pd.DataFrame(extract_groupdict(ctx, pattern))


def df_from_md(
    markup: str,
    start_tag: str,
    headers: list,
    extract_links: list,
) -> pd.DataFrame:
    """Build dataframe from Markdown markup language.

    Args:
        markup (str): Markdown markup language string.
        start_tag (str): Starting reference point HTML to parse the tables from.
        headers (list): Headers of the table.
        extract_links (list): Column to extract href value.
    Notes:
        We are not using the ``read_html`` method from pandas
        to be able to retrieve all href values.

    Returns:
        pd.DataFrame
    """
    html = mistune.html(markup)
    soup = BeautifulSoup(html, "html.parser")
    ret = []

    start = soup.find(start_tag)

    for t in start.next_elements:
        if isinstance(t, Tag) and t.name == "tr":
            tds = t.find_all("td")
            if tds:
                if len(tds) == len(headers):
                    ret.append(parse_tr_record(tds, headers, extract_links))
    return pd.DataFrame(ret)


def export_formatted_df(
    name: str, df: pd.DataFrame, dest: str = DEFAULT_FOLDER
) -> BinaryIO:
    """Export dataframe to formatted Excel worksheet.

    Args:
        name (str): Name of the excel file
        df (pd.DataFrame): [description]
        path (str): Output directory.

    Returns:
        BinaryIO: Excel file.
    """

    path = f"{dest}/XLSX/"
    writer = pd.ExcelWriter(f"{path}/{DEFAULT_PREFIX}_{name}.xlsx", engine="xlsxwriter")
    df.to_excel(writer, sheet_name="Sheet1", startrow=1, header=False, index=False)

    workbook = writer.book
    worksheet = writer.sheets["Sheet1"]

    for column in df.columns:
        # column_width = max(int(df[column].astype(str).str.len().max()), len(column))
        column_width = int(df[column].astype(str).str.len().max())
        col_idx = df.columns.get_loc(column)
        worksheet.set_column(col_idx, col_idx, column_width)

    (max_row, max_col) = df.shape

    column_settings = [{"header": column} for column in df.columns]

    worksheet.add_table(0, 0, max_row, max_col - 1, {"columns": column_settings})

    # Excel table structure

    # worksheet.set_column(0, max_col - 1, 12)
    writer.save()


if __name__ == "__main__":
    for src, p in STEPS.items():
        parser, url = p.get("parser"), p.get("url")

        with requests.get(url) as r:
            ctx = r.text
            if parser == "markdown":
                df = df_from_md(ctx, **p.get("kwargs"))
            elif parser == "regexp":
                df = df_from_regexp(ctx, **p.get("kwargs"))

        df.to_csv(f"{DEFAULT_FOLDER}/CSV/{DEFAULT_PREFIX}_{src}.csv", index=False)

        if src == "NCSC-NL":
            df["Version"] = df["Version"].str.replace("^=", "'=", regex=True)

        export_formatted_df(src, df)

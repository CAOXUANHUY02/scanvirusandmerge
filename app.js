const processData = (data) => {
    const parsedData = JSON.parse(JSON.stringify(data)).results.data;
    const newData = [];

    const { critical: criticalBearerData, medium: mediumBearerData, low: lowBearerData } = parsedData.bearer;
    const oldSemgrepData = parsedData.semgrep.results;

    const mapData = (sourceData) => {
        return sourceData.map(({ cwe_ids, title, description, line_number, full_filename, documentation_url, code_extract }) => ({
            cwe_ids,
            title,
            description,
            line_number,
            full_filename,
            documentation_url,
            code_extract
        }));
    };

    const newCriticalBearerData = mapData(criticalBearerData);
    const newMediumBearerData = mapData(mediumBearerData);
    const newLowBearerData = mapData(lowBearerData);

    newData.push(...newCriticalBearerData, ...newMediumBearerData, ...newLowBearerData);

    oldSemgrepData.forEach((element) => {
        newData.push({
            cwe_ids: element.extra.metadata.cwe[0].split(':')[0].replace('CWE-', ''),
            title: element.check_id,
            description: element.extra.message,
            line_number: element.start.line,
            full_filename: element.path,
            documentation_url: element.extra.metadata.references[0],
            code_extract: element.extra.lines.trim()
        });
    });

    return newData;
};

const processData = (data: string) => {
	const parsedData = JSON.parse(data);
	const newData: Array<{
		cwe_ids: string | string[];
		title: string;
		description: string;
		line_number: number;
		full_filename: string;
		documentation_url: string;
		code_extract: string;
	}> = [];

	if (parsedData.results.bearer) {
		const {
			critical = [],
			high = [],
			medium = [],
			low = [],
		} = parsedData.results.bearer;
		const allBearerResults = [...critical, ...high, ...medium, ...low];

		allBearerResults.forEach((result) => {
			newData.push({
				cwe_ids: result.cwe_ids,
				title: result.title,
				description: result.description,
				line_number: result.line_number,
				full_filename: result.full_filename,
				documentation_url: result.documentation_url,
				code_extract: result.code_extract,
			});
		});
	}

	if (parsedData.results.semgrep?.results) {
		parsedData.results.semgrep.results.forEach(
			(element: {
				check_id: string;
				path: string;
				start: { line: number; col: number };
				extra: {
					lines: string;
					message: string;
					metadata: {
						cwe: string[];
						references?: string[];
					};
				};
			}) => {
				newData.push({
					cwe_ids: element.extra.metadata.cwe[0]
						.split(':')[0]
						.replace('CWE-', ''),
					title: element.check_id,
					description: element.extra.message,
					line_number: element.start.line,
					full_filename: element.path,
					documentation_url:
						element.extra.metadata.references?.[0] ?? '',
					code_extract: element.extra.lines.trim(),
				});
			},
		);
	}

	const uniqueData = newData.reduce<
		Array<{
			cwe_ids: string | string[];
			title: string;
			description: string;
			line_number: number;
			full_filename: string;
			documentation_url: string;
			code_extract: string;
		}>
	>((acc, current) => {
		const isDuplicate = acc.some(
			(item) =>
				(Array.isArray(current.cwe_ids)
					? current.cwe_ids[0]
					: current.cwe_ids) ===
					(Array.isArray(item.cwe_ids)
						? item.cwe_ids[0]
						: item.cwe_ids) &&
				current.line_number === item.line_number &&
				current.full_filename === item.full_filename &&
				current.code_extract === item.code_extract,
		);

		if (!isDuplicate) {
			acc.push(current);
		}

		return acc;
	}, []);

	return uniqueData;
};

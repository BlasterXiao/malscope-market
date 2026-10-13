// 复制这段到 data/usage/<org>/<slug>.js(文件不存在就新建),一个文件里可以有多条 addUsage。
// 新建文件后记得去 data/manifest.js 加一行路径。
FT2.addUsage({
  technique: 'newtechnique',   // 对应 data/techniques.js 里的 id
  org: 'cnc',                  // 对应 data/orgs.js 里的 id
  family: 'SampleFamilyName',  // 家族/样本简称,不用哈希
  date: '2026-01-01',          // 当天日期
  evidence: '一句话证据摘要,不超过一行',
  link: '',                    // 指向那份 techniques.html 的路径,跨机器不强求可点开
});

/**
 * Yile API Operators Module
 * Operator/department information
 */

export default function createOperatorsModule(client) {
  return {
    async getOperatorInfo() {
      return client.request('department/queryDepartment.do', {});
    },

    async getOperatorDetails() {
      const result = await this.getOperatorInfo();
      
      if (!result.success) {
        return result;
      }

      const data = Array.isArray(result.data) ? result.data[0] : result.data;
      
      return {
        success: true,
        operator: {
          id: data?.id,
          name: data?.name,
          address: data?.address,
          contacts: data?.contacts,
          phone: data?.phone,
          email: data?.email,
          createdAt: data?.gmtCreate,
          updatedAt: data?.gmtUpdate
        }
      };
    }
  };
}
